package pkg

import (
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
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
	sort.Stable(rbac.SortableRuleSlice(compactRules))
	return compactRules
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
