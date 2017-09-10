package pkg

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

// RBACObjects holds lists of RBAC API objects
type RBACObjects struct {
	Roles               []*rbac.Role
	RoleBindings        []*rbac.RoleBinding
	ClusterRoles        []*rbac.ClusterRole
	ClusterRoleBindings []*rbac.ClusterRoleBinding
}

// GenerateOptions specifies options for generating RBAC roles
type GenerateOptions struct {
	VerbExpansions                          map[string][]string
	ExpandMultipleNamesToUnnamed            bool
	ExpandMultipleNamespacesToClusterScoped bool

	NamePrefix string
	Labels     map[string]string
}

// DefaultGenerateOptions returns default generation options
func DefaultGenerateOptions() GenerateOptions {
	return GenerateOptions{
		VerbExpansions: map[string][]string{
			"watch":  []string{"get", "list"},
			"list":   []string{"get", "watch"},
			"update": []string{"get", "patch"},
			"patch":  []string{"get", "update"},
		},
		ExpandMultipleNamesToUnnamed:            true,
		ExpandMultipleNamespacesToClusterScoped: true,

		NamePrefix: "audit2rbac",
		Labels:     map[string]string{},
	}
}

// Generator allows generating a set of covering RBAC roles and bindings
type Generator struct {
	Options GenerateOptions

	existing RBACObjects
	requests []authorizer.AttributesRecord

	generated       RBACObjects
	generatedGetter *validation.StaticRoles

	clusterRole           *rbac.ClusterRole
	clusterRoleBinding    *rbac.ClusterRoleBinding
	namespacedRole        map[string]*rbac.Role
	namespacedRoleBinding map[string]*rbac.RoleBinding
}

// NewGenerator creates a new Generator
func NewGenerator(existing RBACObjects, requests []authorizer.AttributesRecord, options GenerateOptions) *Generator {
	_, getter := validation.NewTestRuleResolver(nil, nil, nil, nil)

	return &Generator{
		existing:              existing,
		requests:              requests,
		Options:               options,
		namespacedRole:        map[string]*rbac.Role{},
		namespacedRoleBinding: map[string]*rbac.RoleBinding{},
		generatedGetter:       getter,
	}
}

// Generate returns a set of RBAC roles and bindings that cover the specified requests
func (g *Generator) Generate() *RBACObjects {
	_, existingGetter := validation.NewTestRuleResolver(g.existing.Roles, g.existing.RoleBindings, g.existing.ClusterRoles, g.existing.ClusterRoleBindings)
	existingAuthorizer := rbacauthorizer.New(existingGetter, existingGetter, existingGetter, existingGetter)

	generatedAuthorizer := rbacauthorizer.New(g.generatedGetter, g.generatedGetter, g.generatedGetter, g.generatedGetter)

	// sort requests to put broader ones first
	sortRequests(g.requests)

	for _, request := range g.requests {
		if ok, _, _ := existingAuthorizer.Authorize(request); ok {
			continue
		}
		if ok, _, _ := generatedAuthorizer.Authorize(request); ok {
			continue
		}

		if !request.ResourceRequest {
			clusterRole := g.ensureClusterRoleAndBinding(userToSubject(request.User))
			clusterRole.Rules = append(clusterRole.Rules, rbac.NewRule(request.Verb).URLs(request.Path).RuleOrDie())
			continue
		}

		requestCopy := request
		requestCopy.Name = ""
		requestCopy.Namespace = ""

		if (request.Namespace != "" && g.Options.ExpandMultipleNamespacesToClusterScoped) || (request.Name != "" && g.Options.ExpandMultipleNamesToUnnamed) {
			// search for other requests with the same verb/group/resource/subresource that differ only by name/namespace
			for _, a := range g.requests {
				differentNamespace := a.Namespace != "" && a.Namespace != request.Namespace
				differentName := a.Name != "" && a.Name != request.Name
				a.Name = ""
				a.Namespace = ""
				if reflect.DeepEqual(requestCopy, a) {
					if g.Options.ExpandMultipleNamespacesToClusterScoped && differentNamespace {
						request.Namespace = ""
					}
					if g.Options.ExpandMultipleNamesToUnnamed && differentName {
						request.Name = ""
					}
				}
			}
		}

		if request.Namespace == "" {
			clusterRole := g.ensureClusterRoleAndBinding(userToSubject(request.User))
			clusterRole.Rules = append(clusterRole.Rules, attributesToResourceRule(request, g.Options))
		} else {
			role := g.ensureNamespacedRoleAndBinding(userToSubject(request.User), request.Namespace)
			role.Rules = append(role.Rules, attributesToResourceRule(request, g.Options))
		}
	}

	// Compact rules
	for _, role := range g.generated.ClusterRoles {
		role.Rules = compactRules(role.Rules)
	}
	for _, role := range g.generated.Roles {
		role.Rules = compactRules(role.Rules)
	}

	return &g.generated
}

func (g *Generator) ensureClusterRoleAndBinding(subject rbac.Subject) *rbac.ClusterRole {
	if g.clusterRole != nil {
		return g.clusterRole
	}

	g.clusterRole = &rbac.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: g.Options.NamePrefix, Labels: g.Options.Labels},
	}
	g.clusterRoleBinding = &rbac.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: g.Options.NamePrefix, Labels: g.Options.Labels},
		RoleRef:    rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: g.clusterRole.Name},
		Subjects:   []rbac.Subject{subject},
	}

	g.generated.ClusterRoles = append(g.generated.ClusterRoles, g.clusterRole)
	g.generated.ClusterRoleBindings = append(g.generated.ClusterRoleBindings, g.clusterRoleBinding)

	_, regeneratedGetter := validation.NewTestRuleResolver(g.generated.Roles, g.generated.RoleBindings, g.generated.ClusterRoles, g.generated.ClusterRoleBindings)
	*g.generatedGetter = *regeneratedGetter

	return g.clusterRole
}

func (g *Generator) ensureNamespacedRoleAndBinding(subject rbac.Subject, namespace string) *rbac.Role {
	if g.namespacedRole[namespace] != nil {
		return g.namespacedRole[namespace]
	}

	g.namespacedRole[namespace] = &rbac.Role{
		ObjectMeta: metav1.ObjectMeta{Name: g.Options.NamePrefix, Namespace: namespace, Labels: g.Options.Labels},
	}
	g.namespacedRoleBinding[namespace] = &rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: g.Options.NamePrefix, Namespace: namespace, Labels: g.Options.Labels},
		RoleRef:    rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: g.namespacedRole[namespace].Name},
		Subjects:   []rbac.Subject{subject},
	}

	g.generated.Roles = append(g.generated.Roles, g.namespacedRole[namespace])
	g.generated.RoleBindings = append(g.generated.RoleBindings, g.namespacedRoleBinding[namespace])

	_, regeneratedGetter := validation.NewTestRuleResolver(g.generated.Roles, g.generated.RoleBindings, g.generated.ClusterRoles, g.generated.ClusterRoleBindings)
	*g.generatedGetter = *regeneratedGetter

	return g.namespacedRole[namespace]
}
