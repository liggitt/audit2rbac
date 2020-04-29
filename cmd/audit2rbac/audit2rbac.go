package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	goruntime "runtime"
	"strings"
	"sync"

	"github.com/liggitt/audit2rbac/pkg"
	"github.com/spf13/cobra"

	v1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacv1helper "k8s.io/kubernetes/pkg/apis/rbac/v1"
)

func main() {
	checkErr(os.Stderr, NewAudit2RBACCommand(os.Stdout, os.Stderr).Execute())
}

func checkErr(w io.Writer, err error) {
	if err != nil {
		fmt.Fprintln(w, err)
		os.Exit(1)
	}
}

// NewAudit2RBACCommand builds a new command with default options
func NewAudit2RBACCommand(stdout, stderr io.Writer) *cobra.Command {
	name := "audit2rbac:${user}"
	annotations := []string{"audit2rbac.liggitt.net/version=${version}"}
	labels := []string{"audit2rbac.liggitt.net/user=${user}", "audit2rbac.liggitt.net/generated=true"}

	options := &Audit2RBACOptions{
		GeneratedPath: ".",

		ExpandMultipleNamespacesToClusterScoped: true,
		ExpandMultipleNamesToUnnamed:            true,

		Stdout: stdout,
		Stderr: stderr,

		OutputFormat: "yaml",
	}

	serviceAccount := ""

	showVersion := false

	cmd := &cobra.Command{
		Use:   "audit2rbac --filename=audit.log [ --user=bob | --serviceaccount=my-namespace:my-sa ]",
		Short: "",
		Long:  "",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				fmt.Fprintln(stdout, "audit2rbac version "+pkg.Version)
				return
			}

			checkErr(stderr, options.Complete(serviceAccount, args, name, annotations, labels))

			if err := options.Validate(); err != nil {
				fmt.Fprintln(stderr, err)
				fmt.Fprintln(stderr)
				cmd.Help()
				os.Exit(1)
			}

			checkErr(stderr, options.Run())
		},
	}

	cmd.Flags().StringArrayVarP(&options.AuditSources, "filename", "f", options.AuditSources, "File, URL, or - for STDIN to read audit events from")

	cmd.Flags().StringVar(&options.User, "user", options.User, "User to filter audit events to and generate role bindings for")
	cmd.Flags().StringVar(&serviceAccount, "serviceaccount", serviceAccount, "Service account to filter audit events to and generate role bindings for, in format <namespace>:<name>")

	cmd.Flags().StringVarP(&options.Namespace, "namespace", "n", options.Namespace, "Namespace to filter audit events to")

	cmd.Flags().BoolVar(&options.ExpandMultipleNamespacesToClusterScoped, "expand-multi-namespace", options.ExpandMultipleNamespacesToClusterScoped, "Allow identical operations performed in more than one namespace to be performed in any namespace")
	cmd.Flags().BoolVar(&options.ExpandMultipleNamesToUnnamed, "expand-multi-name", options.ExpandMultipleNamesToUnnamed, "Allow identical operations performed on more than one resource name (e.g. 'get pods pod1' and 'get pods pod2') to be allowed on any name")

	cmd.Flags().StringVar(&name, "generate-name", name, "Name to use for generated objects")
	cmd.Flags().StringSliceVar(&annotations, "generate-annotations", annotations, "Annotations to add to generated objects")
	cmd.Flags().StringSliceVar(&labels, "generate-labels", labels, "Labels to add to generated objects")

	cmd.Flags().StringVarP(&options.OutputFormat, "output-format", "o", options.OutputFormat, "The output format to use (yaml|json)")

	cmd.Flags().BoolVar(&showVersion, "version", false, "Display version")

	return cmd
}

// Audit2RBACOptions holds all the options for the utility
type Audit2RBACOptions struct {
	// AuditSources is a list of files, URLs or - for STDIN.
	// Format must be JSON event.v1alpha1.audit.k8s.io, event.v1beta1.audit.k8s.io,  event.v1.audit.k8s.io objects, one per line
	AuditSources []string

	// ExistingObjectFiles is a list of files or URLs.
	// Format must be JSON or YAML RBAC objects or List.v1 objects.
	ExistingRBACObjectSources []string

	// User to filter audit events to and generate roles for
	User string

	// Namespace limits the audit events considered to the specified namespace
	Namespace string

	// Directory to write generated roles to. Defaults to current directory.
	GeneratedPath string
	// Name for generated objects. Defaults to "audit2rbac:<user>"
	Name string
	// Labels to apply to generated object names.
	Labels map[string]string
	// Annotations to apply to generated object names.
	Annotations map[string]string

	// If the same operation is performed in multiple namespaces, expand the permission to allow it in any namespace
	ExpandMultipleNamespacesToClusterScoped bool
	// If the same operation is performed on resources with different names, expand the permission to allow it on any name
	ExpandMultipleNamesToUnnamed bool

	Stdout io.Writer
	Stderr io.Writer

	//OutputFormat is the format to use. Either yaml or json
	OutputFormat string
}

// Complete is a helper utility to validate and complete the options
func (a *Audit2RBACOptions) Complete(serviceAccount string, args []string, name string, annotations, labels []string) error {
	if len(serviceAccount) > 0 && len(a.User) > 0 {
		return fmt.Errorf("cannot set both user and service account")
	}
	if len(serviceAccount) > 0 {
		parts := strings.Split(serviceAccount, ":")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("service account must be in the format <namespace>:<name>")
		}
		a.User = serviceaccount.MakeUsername(parts[0], parts[1])
	}

	a.Annotations = nil
	for _, s := range annotations {
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			continue
		}
		if a.Annotations == nil {
			a.Annotations = map[string]string{}
		}
		s = strings.Replace(s, "${user}", a.User, -1)
		s = strings.Replace(s, "${version}", pkg.Version, -1)
		parts := strings.SplitN(s, "=", 2)
		if len(parts) == 1 {
			a.Annotations[parts[0]] = ""
		} else {
			a.Annotations[parts[0]] = parts[1]
		}
	}

	a.Labels = nil
	for _, s := range labels {
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			continue
		}
		if a.Labels == nil {
			a.Labels = map[string]string{}
		}
		s = strings.Replace(s, "${user}", sanitizeLabel(a.User), -1)
		s = strings.Replace(s, "${version}", sanitizeLabel(pkg.Version), -1)
		parts := strings.SplitN(s, "=", 2)
		if len(parts) == 1 {
			a.Labels[parts[0]] = ""
		} else {
			a.Labels[parts[0]] = parts[1]
		}
	}

	if len(name) > 0 {
		name = strings.Replace(name, "${user}", sanitizeName(a.User), -1)
		name = strings.Replace(name, "${version}", sanitizeName(pkg.Version), -1)
		a.Name = name
	}

	if a.Stderr == nil {
		a.Stderr = os.Stderr
	}
	if a.Stdout == nil {
		a.Stdout = os.Stdout
	}

	return nil
}

// Validate is a helper to validate that the correct input was specified
func (a *Audit2RBACOptions) Validate() error {
	if len(a.User) == 0 {
		return fmt.Errorf("--user is required")
	}
	if len(a.AuditSources) == 0 {
		return fmt.Errorf("--filename is required")
	}
	if len(a.GeneratedPath) == 0 {
		return fmt.Errorf("--output is required")
	}
	if a.OutputFormat != "yaml" && a.OutputFormat != "json" {
		return fmt.Errorf("--output-format must be one of (yaml|json)")
	}
	return nil
}

// Run is starting point for the utility
func (a *Audit2RBACOptions) Run() error {
	hasErrors := false

	if len(a.AuditSources) == 1 {
		fmt.Fprintln(a.Stderr, "Opening audit source...")
	} else {
		fmt.Fprintln(a.Stderr, "Opening audit sources...")
	}

	streams, streamErrors := openStreams(a.AuditSources)
	for _, err := range streamErrors {
		hasErrors = true
		fmt.Fprintln(os.Stderr, err)
	}

	fmt.Fprint(a.Stderr, "Loading events...")
	results := stream(streams)
	results = flatten(results)
	results = typecast(results, pkg.Scheme)
	results = convertinternal(results, pkg.Scheme)
	results = filterEvents(results,
		func(event *audit.Event) bool {
			eventUser := &event.User
			if event.ImpersonatedUser != nil {
				eventUser = event.ImpersonatedUser
			}
			return eventUser.Username == a.User
		},
		func(event *audit.Event) bool {
			return a.Namespace == "" || (event.ObjectRef != nil && a.Namespace == event.ObjectRef.Namespace)
		},
	)

	// TODO: allow generating intermediate results before completing stream (every X events, or every X seconds, etc)
	// This allows piping the audit log through audit2rbac

	attributes := []authorizer.AttributesRecord{}
	for result := range results {
		if result.err != nil {
			hasErrors = true
			fmt.Fprintln(os.Stderr, result.err)
			continue
		}

		attrs := eventToAttributes(result.obj.(*audit.Event))
		attributes = append(attributes, attrs)
		if len(attributes)%100 == 0 {
			fmt.Fprintf(a.Stderr, ".")
		}
	}
	fmt.Fprintln(a.Stderr)

	if len(attributes) == 0 {
		message := fmt.Sprintf("No audit events matched user %s", a.User)
		if len(a.Namespace) > 0 {
			message += fmt.Sprintf(" in namespace %s", a.Namespace)
		}
		return errors.New(message)
	}

	fmt.Fprintln(a.Stderr, "Evaluating API calls...")

	opts := pkg.DefaultGenerateOptions()
	opts.Labels = a.Labels
	opts.Annotations = a.Annotations
	opts.Name = a.Name
	opts.ExpandMultipleNamespacesToClusterScoped = a.ExpandMultipleNamespacesToClusterScoped
	opts.ExpandMultipleNamesToUnnamed = a.ExpandMultipleNamesToUnnamed

	fmt.Fprintln(a.Stderr, "Generating roles...")
	generated := pkg.NewGenerator(getDiscoveryRoles(), attributes, opts).Generate()

	firstSeparator := true
	printSeparator := func() {

		if firstSeparator {
			firstSeparator = false
			return
		}
		if a.OutputFormat == "yaml" {
			fmt.Fprintln(os.Stdout, "---")
		}
		if a.OutputFormat == "json" {
			fmt.Fprintln(os.Stdout, "")
		}

	}
	for _, obj := range generated.Roles {
		printSeparator()
		pkg.Output(os.Stdout, obj, a.OutputFormat)
	}
	for _, obj := range generated.ClusterRoles {
		printSeparator()
		pkg.Output(os.Stdout, obj, a.OutputFormat)
	}
	for _, obj := range generated.RoleBindings {
		printSeparator()
		pkg.Output(os.Stdout, obj, a.OutputFormat)
	}
	for _, obj := range generated.ClusterRoleBindings {
		printSeparator()
		pkg.Output(os.Stdout, obj, a.OutputFormat)
	}

	fmt.Fprintln(a.Stderr, "\nComplete!")

	if hasErrors {
		return fmt.Errorf("Errors occurred reading audit events")
	}
	return nil
}

func sanitizeName(s string) string {
	return strings.ToLower(string(regexp.MustCompile(`[^a-zA-Z0-9:]`).ReplaceAll([]byte(s), []byte("-"))))
}
func sanitizeLabel(s string) string {
	return strings.ToLower(string(regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAll([]byte(s), []byte("-"))))
}

func openStreams(sources []string) ([]io.ReadCloser, []error) {
	streams := []io.ReadCloser{}
	errors := []error{}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for _, source := range sources {
		if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
			req, err := http.NewRequest("GET", source, nil)
			if err != nil {
				errors = append(errors, err)
				continue
			}

			req.Header.Set("User-Agent", "audit2rbac/"+pkg.Version+" "+goruntime.GOOS+"/"+goruntime.GOARCH)

			resp, err := client.Do(req)
			if err != nil {
				errors = append(errors, err)
			} else if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				errors = append(errors, fmt.Errorf("error fetching %s: %d", source, resp.StatusCode))
			} else {
				streams = append(streams, resp.Body)
			}
		} else if source == "-" {
			streams = append(streams, os.Stdin)
		} else {
			f, err := os.Open(source)
			if err != nil {
				errors = append(errors, err)
			} else {
				streams = append(streams, f)
			}
		}
	}

	return streams, errors
}

type streamObject struct {
	obj runtime.Object
	err error
}

// decoder can decode streaming json, yaml docs, single json objects, single yaml objects
type decoder interface {
	Decode(into interface{}) error
}

func streamingDecoder(r io.ReadCloser) decoder {
	buffer := bufio.NewReaderSize(r, 1024)
	b, _ := buffer.Peek(1)
	if string(b) == "{" {
		return json.NewDecoder(buffer)
	}
	return yaml.NewYAMLToJSONDecoder(buffer)

}

func stream(sources []io.ReadCloser) <-chan *streamObject {
	out := make(chan *streamObject)

	wg := &sync.WaitGroup{}
	for i := range sources {
		wg.Add(1)
		go func(r io.ReadCloser) {
			defer wg.Done()
			defer r.Close()
			d := streamingDecoder(r)
			for {
				obj := &unstructured.Unstructured{}
				err := d.Decode(obj)
				switch {
				case err == io.EOF:
					return
				case err != nil:
					out <- &streamObject{err: err}
				default:
					out <- &streamObject{obj: obj}
				}
			}
		}(sources[i])
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func flatten(in <-chan *streamObject) <-chan *streamObject {
	out := make(chan *streamObject)

	v1List := v1.SchemeGroupVersion.WithKind("List")

	go func() {
		defer close(out)
		for result := range in {
			if result.err != nil {
				out <- result
				continue
			}

			if result.obj.GetObjectKind().GroupVersionKind() != v1List {
				out <- result
				continue
			}

			data, err := json.Marshal(result.obj)
			if err != nil {
				out <- &streamObject{err: err}
				continue
			}

			list := &unstructured.UnstructuredList{}
			if err := list.UnmarshalJSON(data); err != nil {
				out <- &streamObject{err: err}
				continue
			}

			for _, item := range list.Items {
				out <- &streamObject{obj: &item}
			}
		}
	}()
	return out
}

func typecast(in <-chan *streamObject, creator runtime.ObjectCreater) <-chan *streamObject {
	out := make(chan *streamObject)

	go func() {
		defer close(out)
		for result := range in {
			if result.err != nil {
				out <- result
				continue
			}

			typed, err := creator.New(result.obj.GetObjectKind().GroupVersionKind())
			if err != nil {
				out <- &streamObject{err: err}
				continue
			}

			unstructuredObject, ok := result.obj.(*unstructured.Unstructured)
			if !ok {
				out <- &streamObject{err: fmt.Errorf("expected *unstructured.Unstructured, got %T", result.obj)}
			}

			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObject.Object, typed); err != nil {
				out <- &streamObject{err: err}
				continue
			}

			out <- &streamObject{obj: typed}
		}
	}()
	return out
}

func convertinternal(in <-chan *streamObject, convertor runtime.ObjectConvertor) <-chan *streamObject {
	out := make(chan *streamObject)

	go func() {
		defer close(out)
		for result := range in {
			if result.err != nil {
				out <- result
				continue
			}

			gv := result.obj.GetObjectKind().GroupVersionKind().GroupVersion()
			if gv.Version == "" || gv.Version == runtime.APIVersionInternal {
				out <- result
				continue
			}

			gv.Version = runtime.APIVersionInternal
			converted, err := convertor.ConvertToVersion(result.obj, gv)
			if err != nil {
				out <- &streamObject{err: err}
				continue
			}

			out <- &streamObject{obj: converted}
		}
	}()
	return out
}

func filterEvents(in <-chan *streamObject, filters ...func(*audit.Event) bool) <-chan *streamObject {
	out := make(chan *streamObject)

	go func() {
		defer close(out)
		for result := range in {
			if result.err != nil {
				out <- result
				continue
			}

			event, ok := result.obj.(*audit.Event)
			if !ok {
				out <- &streamObject{err: fmt.Errorf("expected *audit.Event, got %T", result.obj)}
				continue
			}

			include := true
			for _, filter := range filters {
				include = filter(event)
				if !include {
					break
				}
			}

			if include {
				out <- result
			}
		}
	}()

	return out
}

func eventToAttributes(event *audit.Event) authorizer.AttributesRecord {
	eventUser := &event.User
	if event.ImpersonatedUser != nil {
		eventUser = event.ImpersonatedUser
	}

	attrs := authorizer.AttributesRecord{
		Verb: event.Verb,
		Path: event.RequestURI,
		User: &user.DefaultInfo{
			Name:   eventUser.Username,
			Groups: eventUser.Groups,
		},
	}

	if event.ObjectRef != nil {
		attrs.ResourceRequest = true
		attrs.Namespace = event.ObjectRef.Namespace
		attrs.Name = event.ObjectRef.Name
		attrs.Resource = event.ObjectRef.Resource
		attrs.Subresource = event.ObjectRef.Subresource
		attrs.APIGroup = event.ObjectRef.APIGroup
		attrs.APIVersion = event.ObjectRef.APIVersion
	}

	return attrs
}

func getDiscoveryRoles() pkg.RBACObjects {
	return pkg.RBACObjects{
		ClusterRoles: []*rbacv1.ClusterRole{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
				Rules: []rbacv1.PolicyRule{
					rbacv1helper.NewRule("get").URLs("/healthz", "/version", "/swagger*", "/openapi*", "/api*").RuleOrDie(),
				},
			},
		},
		ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
				Subjects: []rbacv1.Subject{
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "system:authenticated"},
					{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "system:unauthenticated"},
				},
				RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "system:discovery"},
			},
		},
	}
}
