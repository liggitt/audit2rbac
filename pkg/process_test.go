package pkg

import (
	"fmt"
	"os"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacv1helper "k8s.io/kubernetes/pkg/apis/rbac/v1"
)

func TestProcessOptions(t *testing.T) {
	bob := &user.DefaultInfo{Name: "bob", Groups: []string{"system:authenticated"}}
	existing := RBACObjects{
		ClusterRoles: []*rbacv1.ClusterRole{
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Rules: []rbacv1.PolicyRule{
					rbacv1helper.NewRule("*").Groups("*").Resources("*").RuleOrDie(),
					rbacv1helper.NewRule("*").URLs("*").RuleOrDie(),
				},
			},
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
				Rules: []rbacv1.PolicyRule{
					rbacv1helper.NewRule("get").URLs("/healthz", "/version", "/swaggerapi", "/swaggerapi/*", "/api", "/api/*", "/apis", "/apis/*").RuleOrDie(),
				},
			},
		},
		ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "system:masters"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
			},
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "system:authenticated"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "system:discovery"},
			},
		},
	}

	testcases := []struct {
		name     string
		opts     GenerateOptions
		requests []authorizer.AttributesRecord
		expected RBACObjects
	}{
		{
			name:     "empty",
			opts:     DefaultGenerateOptions(),
			requests: []authorizer.AttributesRecord{},
			expected: RBACObjects{},
		},
		{
			name: "already allowed by existing",
			opts: DefaultGenerateOptions(),
			requests: []authorizer.AttributesRecord{
				authorizer.AttributesRecord{User: bob, ResourceRequest: false, Verb: "get", Path: "/api"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: false, Verb: "get", Path: "/apis"},
			},
			expected: RBACObjects{},
		},
		{
			name: "nonresource",
			opts: DefaultGenerateOptions(),
			requests: []authorizer.AttributesRecord{
				authorizer.AttributesRecord{User: bob, ResourceRequest: false, Verb: "get", Path: "/foo"},
			},
			expected: RBACObjects{
				ClusterRoles: []*rbacv1.ClusterRole{&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules:      []rbacv1.PolicyRule{rbacv1helper.NewRule("get").URLs("/foo").RuleOrDie()},
				}},
				ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
			},
		},

		{
			name: "cluster-scoped named resource",
			opts: DefaultGenerateOptions(),
			requests: []authorizer.AttributesRecord{
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", APIGroup: "", Resource: "nodes", Name: "mynode"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", APIGroup: "storage.k8s.io", Resource: "storageclasses", Name: "mysc"},
			},
			expected: RBACObjects{
				ClusterRoles: []*rbacv1.ClusterRole{&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacv1.PolicyRule{
						rbacv1helper.NewRule("get").Groups("").Resources("nodes").Names("mynode").RuleOrDie(),
						rbacv1helper.NewRule("get").Groups("storage.k8s.io").Resources("storageclasses").Names("mysc").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
			},
		},
		{
			name: "cluster-scoped named resources with name expansion",
			opts: DefaultGenerateOptions(),
			requests: []authorizer.AttributesRecord{
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Resource: "nodes", Name: "node1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Resource: "nodes", Name: "node2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", APIGroup: "storage.k8s.io", Resource: "storageclasses", Name: "sc1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", APIGroup: "storage.k8s.io", Resource: "storageclasses", Name: "sc2"},
			},
			expected: RBACObjects{
				ClusterRoles: []*rbacv1.ClusterRole{&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacv1.PolicyRule{
						rbacv1helper.NewRule("get").Groups("").Resources("nodes").RuleOrDie(),
						rbacv1helper.NewRule("get").Groups("storage.k8s.io").Resources("storageclasses").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
			},
		},
		{
			name: "cluster-scoped named resources without name expansion",
			opts: func() GenerateOptions {
				opts := DefaultGenerateOptions()
				opts.ExpandMultipleNamesToUnnamed = false
				return opts
			}(),
			requests: []authorizer.AttributesRecord{
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Resource: "nodes", Name: "node1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Resource: "nodes", Name: "node2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", APIGroup: "storage.k8s.io", Resource: "storageclasses", Name: "sc1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", APIGroup: "storage.k8s.io", Resource: "storageclasses", Name: "sc2"},
			},
			expected: RBACObjects{
				ClusterRoles: []*rbacv1.ClusterRole{&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacv1.PolicyRule{
						rbacv1helper.NewRule("get").Groups("").Resources("nodes").Names("node1", "node2").RuleOrDie(),
						rbacv1helper.NewRule("get").Groups("storage.k8s.io").Resources("storageclasses").Names("sc1", "sc2").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
			},
		},
		{
			name: "cluster-scoped named resources without name expansion with covering verb expansion",
			opts: func() GenerateOptions {
				opts := DefaultGenerateOptions()
				opts.ExpandMultipleNamesToUnnamed = false
				return opts
			}(),
			requests: []authorizer.AttributesRecord{
				// list requests should sort to the front, be processed first, expand to get+list+watch, and cover the individual get requests
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Resource: "nodes", Name: "node1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Resource: "nodes", Name: "node2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", APIGroup: "storage.k8s.io", Resource: "storageclasses", Name: "sc1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", APIGroup: "storage.k8s.io", Resource: "storageclasses", Name: "sc2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "list", Resource: "nodes"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "list", APIGroup: "storage.k8s.io", Resource: "storageclasses"},
			},
			expected: RBACObjects{
				ClusterRoles: []*rbacv1.ClusterRole{&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacv1.PolicyRule{
						rbacv1helper.NewRule("get", "list", "watch").Groups("").Resources("nodes").RuleOrDie(),
						rbacv1helper.NewRule("get", "list", "watch").Groups("storage.k8s.io").Resources("storageclasses").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
			},
		},

		{
			name: "namespaced named resources",
			opts: DefaultGenerateOptions(),
			requests: []authorizer.AttributesRecord{
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "configmaps", Name: "cm1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod1"},
			},
			expected: RBACObjects{
				Roles: []*rbacv1.Role{
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						Rules:      []rbacv1.PolicyRule{rbacv1helper.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie()},
					},
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						Rules:      []rbacv1.PolicyRule{rbacv1helper.NewRule("get").Groups("").Resources("pods").Names("pod1").RuleOrDie()},
					},
				},
				RoleBindings: []*rbacv1.RoleBinding{
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
				},
			},
		},

		{
			name: "namespaced named resources with namespace and name expansion",
			opts: DefaultGenerateOptions(),
			requests: []authorizer.AttributesRecord{
				// will get namespaced single-name access to this
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "configmaps", Name: "cm1"},
				// will get cluster-wide access across names to pods and deployments
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "pods", Name: "pod2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "apps", Resource: "deployments", Name: "dep2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep2"},
			},
			expected: RBACObjects{
				ClusterRoles: []*rbacv1.ClusterRole{&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacv1.PolicyRule{
						rbacv1helper.NewRule("get").Groups("").Resources("pods").RuleOrDie(),
						rbacv1helper.NewRule("get").Groups("apps").Resources("deployments").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
				Roles: []*rbacv1.Role{&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
					Rules: []rbacv1.PolicyRule{
						rbacv1helper.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie(),
					},
				}},
				RoleBindings: []*rbacv1.RoleBinding{&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
			},
		},

		{
			name: "namespaced named resources with namespace expansion",
			opts: func() GenerateOptions {
				opts := DefaultGenerateOptions()
				opts.ExpandMultipleNamesToUnnamed = false
				opts.ExpandMultipleNamespacesToClusterScoped = true
				return opts
			}(),
			requests: []authorizer.AttributesRecord{
				// will get namespaced single-name access to this
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "configmaps", Name: "cm1"},
				// will get cluster-wide access to these specific names
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				// will get namespaced access to these specific names
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "", Resource: "pods", Name: "pod3"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "apps", Resource: "deployments", Name: "dep3"},
			},
			expected: RBACObjects{
				ClusterRoles: []*rbacv1.ClusterRole{&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacv1.PolicyRule{
						rbacv1helper.NewRule("get").Groups("").Resources("pods").Names("pod1").RuleOrDie(),
						rbacv1helper.NewRule("get").Groups("apps").Resources("deployments").Names("dep1").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
				Roles: []*rbacv1.Role{
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						Rules:      []rbacv1.PolicyRule{rbacv1helper.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie()},
					},
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						Rules: []rbacv1.PolicyRule{
							rbacv1helper.NewRule("get").Groups("").Resources("pods").Names("pod2").RuleOrDie(),
							rbacv1helper.NewRule("get").Groups("apps").Resources("deployments").Names("dep2").RuleOrDie(),
						},
					},
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						Rules: []rbacv1.PolicyRule{
							rbacv1helper.NewRule("get").Groups("").Resources("pods").Names("pod3").RuleOrDie(),
							rbacv1helper.NewRule("get").Groups("apps").Resources("deployments").Names("dep3").RuleOrDie(),
						},
					},
				},
				RoleBindings: []*rbacv1.RoleBinding{
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
				},
			},
		},

		{
			name: "namespaced named resources with name expansion",
			opts: func() GenerateOptions {
				opts := DefaultGenerateOptions()
				opts.ExpandMultipleNamesToUnnamed = true
				opts.ExpandMultipleNamespacesToClusterScoped = false
				return opts
			}(),
			requests: []authorizer.AttributesRecord{
				// will get namespaced single-name access to this
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "configmaps", Name: "cm1"},
				// will get namespaced access to any name
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod2"},
				// will get namespaced access to any name
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "", Resource: "pods", Name: "pod3"},
				// will get namespaced access to any name
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep2"},
				// will get namespaced access to any name
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "apps", Resource: "deployments", Name: "dep3"},
			},
			expected: RBACObjects{
				Roles: []*rbacv1.Role{
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						Rules:      []rbacv1.PolicyRule{rbacv1helper.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie()},
					},
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						Rules: []rbacv1.PolicyRule{
							rbacv1helper.NewRule("get").Groups("").Resources("pods").RuleOrDie(),
							rbacv1helper.NewRule("get").Groups("apps").Resources("deployments").RuleOrDie(),
						},
					},
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						Rules: []rbacv1.PolicyRule{
							rbacv1helper.NewRule("get").Groups("").Resources("pods").RuleOrDie(),
							rbacv1helper.NewRule("get").Groups("apps").Resources("deployments").RuleOrDie(),
						},
					},
				},
				RoleBindings: []*rbacv1.RoleBinding{
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
				},
			},
		},

		{
			name: "namespaced named resources without name or namespace expansion",
			opts: func() GenerateOptions {
				opts := DefaultGenerateOptions()
				opts.ExpandMultipleNamesToUnnamed = false
				opts.ExpandMultipleNamespacesToClusterScoped = false
				return opts
			}(),
			requests: []authorizer.AttributesRecord{
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "configmaps", Name: "cm1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "", Resource: "pods", Name: "pod3"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "apps", Resource: "deployments", Name: "dep3"},
			},
			expected: RBACObjects{
				Roles: []*rbacv1.Role{
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						Rules:      []rbacv1.PolicyRule{rbacv1helper.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie()},
					},
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						Rules: []rbacv1.PolicyRule{
							rbacv1helper.NewRule("get").Groups("").Resources("pods").Names("pod1", "pod2").RuleOrDie(),
							rbacv1helper.NewRule("get").Groups("apps").Resources("deployments").Names("dep1", "dep2").RuleOrDie(),
						},
					},
					&rbacv1.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						Rules: []rbacv1.PolicyRule{
							rbacv1helper.NewRule("get").Groups("").Resources("pods").Names("pod1", "pod3").RuleOrDie(),
							rbacv1helper.NewRule("get").Groups("apps").Resources("deployments").Names("dep1", "dep3").RuleOrDie(),
						},
					},
				},
				RoleBindings: []*rbacv1.RoleBinding{
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacv1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
				},
			},
		},

		{
			name: "namespaced named resources without name or namespace expansion with covering cluster operation",
			opts: func() GenerateOptions {
				opts := DefaultGenerateOptions()
				opts.ExpandMultipleNamesToUnnamed = false
				opts.ExpandMultipleNamespacesToClusterScoped = false
				return opts
			}(),
			requests: []authorizer.AttributesRecord{
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns1", APIGroup: "", Resource: "configmaps", Name: "cm1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "", Resource: "pods", Name: "pod2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "", Resource: "pods", Name: "pod1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "", Resource: "pods", Name: "pod3"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns2", APIGroup: "apps", Resource: "deployments", Name: "dep2"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "apps", Resource: "deployments", Name: "dep1"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "get", Namespace: "ns3", APIGroup: "apps", Resource: "deployments", Name: "dep3"},
				// list requests sort first, expand to list+get+watch, cover namespaced get operations
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "list", APIGroup: "apps", Resource: "deployments"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "list", APIGroup: "", Resource: "configmaps"},
				authorizer.AttributesRecord{User: bob, ResourceRequest: true, Verb: "list", APIGroup: "", Resource: "pods"},
			},
			expected: RBACObjects{
				ClusterRoles: []*rbacv1.ClusterRole{&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacv1.PolicyRule{
						rbacv1helper.NewRule("get", "list", "watch").Groups("").Resources("configmaps", "pods").RuleOrDie(),
						rbacv1helper.NewRule("get", "list", "watch").Groups("apps").Resources("deployments").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacv1.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacv1.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
			},
		},
	}

	for i := range testcases {
		(func(i int) {
			tc := testcases[i]
			t.Run(tc.name, func(t *testing.T) {
				generator := NewGenerator(existing, tc.requests, tc.opts)
				generated := generator.Generate()
				if !equality.Semantic.DeepEqual(tc.expected.ClusterRoles, generated.ClusterRoles) {
					t.Error("unexpected cluster roles\n", diff.ObjectGoPrintSideBySide(tc.expected.ClusterRoles, generated.ClusterRoles))
				}
				if !equality.Semantic.DeepEqual(tc.expected.ClusterRoleBindings, generated.ClusterRoleBindings) {
					t.Error("unexpected cluster role bindings\n", diff.ObjectGoPrintSideBySide(tc.expected.ClusterRoleBindings, generated.ClusterRoleBindings))
				}
				if !equality.Semantic.DeepEqual(tc.expected.Roles, generated.Roles) {
					t.Error("unexpected roles\n", diff.ObjectGoPrintSideBySide(tc.expected.Roles, generated.Roles))
				}
				if !equality.Semantic.DeepEqual(tc.expected.RoleBindings, generated.RoleBindings) {
					t.Error("unexpected role bindings\n", diff.ObjectGoPrintSideBySide(tc.expected.RoleBindings, generated.RoleBindings))
				}
			})
		})(i)
	}
}

func TestProcess(t *testing.T) {
	bob := &user.DefaultInfo{Name: "bob", Groups: []string{"system:authenticated"}}
	existing := RBACObjects{
		ClusterRoles: []*rbacv1.ClusterRole{
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Rules: []rbacv1.PolicyRule{
					rbacv1helper.NewRule("*").Groups("*").Resources("*").RuleOrDie(),
					rbacv1helper.NewRule("*").URLs("*").RuleOrDie(),
				},
			},
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
				Rules: []rbacv1.PolicyRule{
					rbacv1helper.NewRule("get").URLs("/healthz", "/version", "/swaggerapi", "/swaggerapi/*", "/api", "/api/*", "/apis", "/apis/*").RuleOrDie(),
				},
			},
		},
		ClusterRoleBindings: []*rbacv1.ClusterRoleBinding{
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "system:masters"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
			},
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "system:authenticated"}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "system:discovery"},
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
