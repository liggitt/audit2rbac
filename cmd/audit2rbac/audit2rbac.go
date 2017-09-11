package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/liggitt/audit2rbac/pkg"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	unstructuredconversion "k8s.io/apimachinery/pkg/conversion/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
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

func NewAudit2RBACCommand(stdout, stderr io.Writer) *cobra.Command {
	options := &Audit2RBACOptions{
		GeneratedPath:       ".",
		GeneratedNamePrefix: "",
		GeneratedLabels:     map[string]string{},

		Stdout: stdout,
		Stderr: stderr,
	}

	showVersion := false

	cmd := &cobra.Command{
		Use:   "audit2rbac --filename=audit.log --user=bob",
		Short: "",
		Long:  "",
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				fmt.Fprintln(stdout, "audit2rbac version "+pkg.Version)
				return
			}

			checkErr(stderr, options.Complete(args))

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
	cmd.Flags().StringVarP(&options.User, "user", "u", options.User, "User to filter audit events to and generate role bindings for")
	cmd.Flags().BoolVar(&showVersion, "version", false, "Display version")

	return cmd
}

type Audit2RBACOptions struct {
	// AuditSources is a list of files, URLs or - for STDIN.
	// Format must be JSON event.v1alpha1.audit.k8s.io or event.v1beta1.audit.k8s.io objects, one per line
	AuditSources []string

	// ExistingObjectFiles is a list of files or URLs.
	// Format must be JSON or YAML RBAC objects or List.v1 objects.
	ExistingRBACObjectSources []string

	// User to filter audit events to and generate roles for
	User string

	// Directory to write generated roles to. Defaults to current directory.
	GeneratedPath string
	// Prefix for generated object names. Defaults to "audit2rbac:<user>"
	GeneratedNamePrefix string
	// Labels to apply to generated object names. Defaults to audit2rbac.liggitt.net/generated=true
	GeneratedLabels map[string]string

	Stdout io.Writer
	Stderr io.Writer
}

func (a *Audit2RBACOptions) Complete(args []string) error {
	if len(a.GeneratedLabels) == 0 {
		a.GeneratedLabels["audit2rbac.liggitt.net/user"] = sanitizeLabel(a.User)
		a.GeneratedLabels["audit2rbac.liggitt.net/generated"] = "true"
	}

	if len(a.GeneratedNamePrefix) == 0 {
		user := a.User
		if _, name, err := serviceaccount.SplitUsername(a.User); err == nil && name != "default" {
			user = name
		}
		a.GeneratedNamePrefix = "audit2rbac:" + sanitizeName(user)
	}

	if a.Stderr == nil {
		a.Stderr = os.Stderr
	}
	if a.Stdout == nil {
		a.Stdout = os.Stdout
	}

	return nil
}

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
	return nil
}

func (a *Audit2RBACOptions) Run() error {
	hasErrors := false

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
	results = filterEvents(results, a.User)

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

	if len(attributes) == 0 {
		return fmt.Errorf("No audit events matched user %s", a.User)
	}

	fmt.Fprintln(a.Stderr)
	fmt.Fprintln(a.Stderr, "Evaluating API calls...")

	opts := pkg.DefaultGenerateOptions()
	opts.Labels = a.GeneratedLabels
	opts.NamePrefix = a.GeneratedNamePrefix

	generated := pkg.NewGenerator(pkg.RBACObjects{}, attributes, opts).Generate()

	fmt.Fprintln(a.Stderr, "Generating roles...")

	firstSeparator := true
	printSeparator := func() {
		if firstSeparator {
			firstSeparator = false
			return
		}
		fmt.Fprintln(os.Stdout, "---")
	}
	for _, obj := range generated.ClusterRoles {
		printSeparator()
		pkg.Output(os.Stdout, obj, "yaml")
	}
	for _, obj := range generated.ClusterRoleBindings {
		printSeparator()
		pkg.Output(os.Stdout, obj, "yaml")
	}
	for _, obj := range generated.Roles {
		printSeparator()
		pkg.Output(os.Stdout, obj, "yaml")
	}
	for _, obj := range generated.RoleBindings {
		printSeparator()
		pkg.Output(os.Stdout, obj, "yaml")
	}

	fmt.Fprintln(a.Stderr, "Complete!")

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
			resp, err := client.Get(source)
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
	} else {
		return yaml.NewYAMLToJSONDecoder(buffer)
	}
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

			if err := unstructuredconversion.DefaultConverter.FromUnstructured(unstructuredObject.Object, typed); err != nil {
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

func filterEvents(in <-chan *streamObject, user string) <-chan *streamObject {
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

			eventUser := &event.User
			if event.ImpersonatedUser != nil {
				eventUser = event.ImpersonatedUser
			}
			if eventUser.Username != user {
				continue
			}

			out <- result
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
		// TODO: fix when newer version of apiserver repo is pushed
		// attrs.APIGroup=event.ObjectRef.APIGroup
		attrs.APIVersion = event.ObjectRef.APIVersion
	}

	return attrs
}
