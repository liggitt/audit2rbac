package pkg

import (
	"fmt"
	"os"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacinternal "k8s.io/kubernetes/pkg/apis/rbac"
)

func TestProcess(t *testing.T) {
	bob := &user.DefaultInfo{Name: "bob", Groups: []string{"system:authenticated"}}
	existing := RBACObjects{
		ClusterRoles: []*rbacinternal.ClusterRole{
			&rbacinternal.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Rules: []rbacinternal.PolicyRule{
					rbacinternal.NewRule("*").Groups("*").Resources("*").RuleOrDie(),
					rbacinternal.NewRule("*").URLs("*").RuleOrDie(),
				},
			},
			&rbacinternal.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
				Rules: []rbacinternal.PolicyRule{
					rbacinternal.NewRule("get").URLs("/healthz", "/version", "/swaggerapi", "/swaggerapi/*", "/api", "/api/*", "/apis", "/apis/*").RuleOrDie(),
				},
			},
		},
		ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{
			&rbacinternal.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Subjects:   []rbacinternal.Subject{{Kind: rbacinternal.GroupKind, APIGroup: rbacinternal.GroupName, Name: "system:masters"}},
				RoleRef:    rbacinternal.RoleRef{APIGroup: rbacinternal.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
			},
			&rbacinternal.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
				Subjects:   []rbacinternal.Subject{{Kind: rbacinternal.GroupKind, APIGroup: rbacinternal.GroupName, Name: "system:authenticated"}},
				RoleRef:    rbacinternal.RoleRef{APIGroup: rbacinternal.GroupName, Kind: "ClusterRole", Name: "system:discovery"},
			},
		},
	}

	requests := []authorizer.AttributesRecord{
		// permissions already included in discovery roles
		authorizer.AttributesRecord{User: bob, ResourceRequest: false, Verb: "get", Path: "/api"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: false, Verb: "get", Path: "/apis"},

		// permissions not included in discovery roles, should be in cluster role
		authorizer.AttributesRecord{User: bob, ResourceRequest: false, Verb: "get", Path: "/ui"},

		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "create", Namespace: "", APIGroup: "", Resource: "nodes", Name: ""},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "create", Namespace: "", APIGroup: "", Resource: "nodes", Name: ""},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "", APIGroup: "", Resource: "nodes", Name: "node1"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "update", Namespace: "", APIGroup: "", Resource: "nodes", Name: "node1"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "", APIGroup: "", Resource: "nodes", Name: "node2"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "update", Namespace: "", APIGroup: "", Resource: "nodes", Name: "node2"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "list", Namespace: "", APIGroup: "", Resource: "nodes", Name: ""},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "watch", Namespace: "", APIGroup: "", Resource: "nodes", Name: ""},

		// operations across names, across namespaces, should end up as a cluster-level permission
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "list", Namespace: "", APIGroup: "", Resource: "pods", Name: ""},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "watch", Namespace: "", APIGroup: "", Resource: "pods", Name: ""},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "pods", Name: "pod1"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "pods", Name: "pod2"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod3"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod4"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "update", Namespace: "ns1", APIGroup: "", Resource: "pods", Subresource: "status", Name: "pod1"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "update", Namespace: "ns1", APIGroup: "", Resource: "pods", Subresource: "status", Name: "pod2"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "update", Namespace: "ns2", APIGroup: "", Resource: "pods", Subresource: "status", Name: "pod3"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "update", Namespace: "ns2", APIGroup: "", Resource: "pods", Subresource: "status", Name: "pod4"},

		// configmap write permissions for a lock, should only end up in a namespaced role
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "create", Namespace: "kube-system", APIGroup: "", Resource: "configmaps", Name: ""},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "kube-system", APIGroup: "", Resource: "configmaps", Name: "mylock"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "update", Namespace: "kube-system", APIGroup: "", Resource: "configmaps", Name: "mylock"},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "list", Namespace: "kube-system", APIGroup: "", Resource: "configmaps", Name: ""},
		authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "watch", Namespace: "kube-system", APIGroup: "", Resource: "configmaps", Name: ""},
	}
	generator := NewGenerator(existing, requests, DefaultGenerateOptions())
	generated := generator.Generate()

	for _, obj := range generated.ClusterRoles {
		Output(os.Stdout, obj, "yaml")
		fmt.Println()
	}
	for _, obj := range generated.ClusterRoleBindings {
		Output(os.Stdout, obj, "yaml")
		fmt.Println()
	}
	for _, obj := range generated.Roles {
		Output(os.Stdout, obj, "yaml")
		fmt.Println()
	}
	for _, obj := range generated.RoleBindings {
		Output(os.Stdout, obj, "yaml")
		fmt.Println()
	}
}
