package pkg

import (
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/apis/audit"
	auditv1alpha1 "k8s.io/apiserver/pkg/apis/audit/v1alpha1"
	auditv1beta1 "k8s.io/apiserver/pkg/apis/audit/v1beta1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

func userToSubject(user user.Info) rbac.Subject {
	if ns, name, err := serviceaccount.SplitUsername(user.GetName()); err == nil {
		return rbac.Subject{Name: name, Namespace: ns, Kind: "ServiceAccount"}
	}
	return rbac.Subject{Name: user.GetName(), Kind: "User", APIGroup: rbac.GroupName}
}

func attributesToResourceRule(request authorizer.AttributesRecord, options GenerateOptions) rbac.PolicyRule {
	verbs := append([]string{request.Verb}, options.VerbExpansions[request.Verb]...)
	rule := rbac.NewRule(verbs...).Groups(request.APIGroup).Resources(request.Resource).RuleOrDie()
	if request.Subresource != "" {
		rule.Resources[0] = rule.Resources[0] + "/" + request.Subresource
	}
	if request.Name != "" {
		rule.ResourceNames = []string{request.Name}
	}
	return rule
}

func compactRules(rules []rbac.PolicyRule) []rbac.PolicyRule {
	breakdownRules := []rbac.PolicyRule{}
	for _, rule := range rules {
		breakdownRules = append(breakdownRules, validation.BreakdownRule(rule)...)
	}
	compactRules, err := validation.CompactRules(breakdownRules)
	if err != nil {
		return rules
	}
	// TODO: fix CompactRules to dedupe verbs
	for i := range compactRules {
		compactRules[i].Verbs = sets.NewString(compactRules[i].Verbs...).List()
	}

	accumulatingRules := []rbac.PolicyRule{}
	for _, rule := range compactRules {
		// Non-resource rules just accumulate
		if len(rule.Resources) == 0 {
			accumulatingRules = append(accumulatingRules, rule)
			continue
		}

		accumulated := false
		// strip resource
		resourcelessRule := rule
		resourcelessRule.Resources = nil
		for j, accumulatingRule := range accumulatingRules {
			// strip resource
			resourcelessAccumulatingRule := accumulatingRule
			resourcelessAccumulatingRule.Resources = nil

			// if all other fields are identical (api group, verbs, names, etc, accumulate resources)
			if reflect.DeepEqual(resourcelessRule, resourcelessAccumulatingRule) {
				combinedResources := sets.NewString(accumulatingRule.Resources...)
				combinedResources.Insert(rule.Resources...)
				accumulatingRule.Resources = combinedResources.List()
				accumulatingRules[j] = accumulatingRule
				accumulated = true
				break
			}
		}
		if !accumulated {
			accumulatingRules = append(accumulatingRules, rule)
		}
	}

	sort.SliceStable(accumulatingRules, func(i, j int) bool {
		// TODO: fix upstream sorting to prioritize API group
		if c := strings.Compare(strings.Join(accumulatingRules[i].APIGroups, ","), strings.Join(accumulatingRules[j].APIGroups, ",")); c != 0 {
			return c < 0
		}
		return strings.Compare(accumulatingRules[i].CompactString(), accumulatingRules[j].CompactString()) < 0
	})
	return accumulatingRules
}

func sortRequests(requests []authorizer.AttributesRecord) {
	sort.SliceStable(requests, func(i, j int) bool {
		// non-resource < resource
		if requests[i].ResourceRequest != requests[j].ResourceRequest {
			return !requests[i].ResourceRequest
		}

		switch {
		case requests[i].ResourceRequest:
			// cluster-scoped < namespaced
			if n1, n2 := len(requests[i].Namespace) == 0, len(requests[j].Namespace) == 0; n1 != n2 {
				return n1
			}

			// unnamed < named
			if n1, n2 := len(requests[i].Name) == 0, len(requests[j].Name) == 0; n1 != n2 {
				return n1
			}

			// list < get
			if requests[i].Verb == "list" && requests[j].Verb == "get" {
				return true
			}
			if requests[i].Verb == "get" && requests[j].Verb == "list" {
				return false
			}

			// Sort by group,resource,subresource,namespace,name,verb
			if c := strings.Compare(requests[i].APIGroup, requests[j].APIGroup); c != 0 {
				return c < 0
			}
			if c := strings.Compare(requests[i].Resource, requests[j].Resource); c != 0 {
				return c < 0
			}
			if c := strings.Compare(requests[i].Subresource, requests[j].Subresource); c != 0 {
				return c < 0
			}
			if c := strings.Compare(requests[i].Namespace, requests[j].Namespace); c != 0 {
				return c < 0
			}
			if c := strings.Compare(requests[i].Name, requests[j].Name); c != 0 {
				return c < 0
			}
			if c := strings.Compare(requests[i].Verb, requests[j].Verb); c != 0 {
				return c < 0
			}

		case !requests[i].ResourceRequest:
			// Sort by verb,path
			if c := strings.Compare(requests[i].Verb, requests[j].Verb); c != 0 {
				return c < 0
			}
			if c := strings.Compare(requests[i].Path, requests[j].Path); c != 0 {
				return c < 0
			}
		}

		return false
	})
}

var (
	// Scheme knows about audit and rbac types
	Scheme = runtime.NewScheme()
	// Decoder knows how to decode audit and rbac objects
	Decoder runtime.Decoder
)

func init() {
	if err := rbacv1.AddToScheme(Scheme); err != nil {
		panic(err)
	}
	if err := rbac.AddToScheme(Scheme); err != nil {
		panic(err)
	}

	if err := auditv1beta1.AddToScheme(Scheme); err != nil {
		panic(err)
	}
	if err := auditv1alpha1.AddToScheme(Scheme); err != nil {
		panic(err)
	}
	if err := audit.AddToScheme(Scheme); err != nil {
		panic(err)
	}

	Decoder = serializer.NewCodecFactory(Scheme).UniversalDecoder()
}

// Output writes the specified object to the specified writer in "yaml" or "json" format
func Output(w io.Writer, obj runtime.Object, format string) error {
	var s *json.Serializer
	switch format {
	case "json":
		s = json.NewSerializer(json.DefaultMetaFactory, Scheme, Scheme, true)
	case "yaml":
		s = json.NewYAMLSerializer(json.DefaultMetaFactory, Scheme, Scheme)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}

	codec := serializer.NewCodecFactory(Scheme).CodecForVersions(s, s, rbacv1.SchemeGroupVersion, rbacv1.SchemeGroupVersion)

	return codec.Encode(obj, w)
}
