package pkg

import (
	"fmt"
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacinternal "k8s.io/kubernetes/pkg/apis/rbac"
)

func TestProcessOptions(t *testing.T) {
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
				ClusterRoles: []*rbacinternal.ClusterRole{&rbacinternal.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules:      []rbacinternal.PolicyRule{rbacinternal.NewRule("get").URLs("/foo").RuleOrDie()},
				}},
				ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{&rbacinternal.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				ClusterRoles: []*rbacinternal.ClusterRole{&rbacinternal.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacinternal.PolicyRule{
						rbacinternal.NewRule("get").Groups("").Resources("nodes").Names("mynode").RuleOrDie(),
						rbacinternal.NewRule("get").Groups("storage.k8s.io").Resources("storageclasses").Names("mysc").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{&rbacinternal.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				ClusterRoles: []*rbacinternal.ClusterRole{&rbacinternal.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacinternal.PolicyRule{
						rbacinternal.NewRule("get").Groups("").Resources("nodes").RuleOrDie(),
						rbacinternal.NewRule("get").Groups("storage.k8s.io").Resources("storageclasses").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{&rbacinternal.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				ClusterRoles: []*rbacinternal.ClusterRole{&rbacinternal.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacinternal.PolicyRule{
						// TODO: improve compaction to make this a single rule referencing two names
						rbacinternal.NewRule("get").Groups("").Resources("nodes").Names("node1").RuleOrDie(),
						rbacinternal.NewRule("get").Groups("").Resources("nodes").Names("node2").RuleOrDie(),
						// TODO: improve compaction to make this a single rule referencing two names
						rbacinternal.NewRule("get").Groups("storage.k8s.io").Resources("storageclasses").Names("sc1").RuleOrDie(),
						rbacinternal.NewRule("get").Groups("storage.k8s.io").Resources("storageclasses").Names("sc2").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{&rbacinternal.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				ClusterRoles: []*rbacinternal.ClusterRole{&rbacinternal.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacinternal.PolicyRule{
						rbacinternal.NewRule("get", "list", "watch").Groups("").Resources("nodes").RuleOrDie(),
						rbacinternal.NewRule("get", "list", "watch").Groups("storage.k8s.io").Resources("storageclasses").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{&rbacinternal.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				Roles: []*rbacinternal.Role{
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						Rules:      []rbacinternal.PolicyRule{rbacinternal.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie()},
					},
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						Rules:      []rbacinternal.PolicyRule{rbacinternal.NewRule("get").Groups("").Resources("pods").Names("pod1").RuleOrDie()},
					},
				},
				RoleBindings: []*rbacinternal.RoleBinding{
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				ClusterRoles: []*rbacinternal.ClusterRole{&rbacinternal.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacinternal.PolicyRule{
						rbacinternal.NewRule("get").Groups("").Resources("pods").RuleOrDie(),
						rbacinternal.NewRule("get").Groups("apps").Resources("deployments").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{&rbacinternal.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
				Roles: []*rbacinternal.Role{&rbacinternal.Role{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
					Rules: []rbacinternal.PolicyRule{
						rbacinternal.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie(),
					},
				}},
				RoleBindings: []*rbacinternal.RoleBinding{&rbacinternal.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				ClusterRoles: []*rbacinternal.ClusterRole{&rbacinternal.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacinternal.PolicyRule{
						rbacinternal.NewRule("get").Groups("").Resources("pods").Names("pod1").RuleOrDie(),
						rbacinternal.NewRule("get").Groups("apps").Resources("deployments").Names("dep1").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{&rbacinternal.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
				}},
				Roles: []*rbacinternal.Role{
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						Rules:      []rbacinternal.PolicyRule{rbacinternal.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie()},
					},
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						Rules: []rbacinternal.PolicyRule{
							rbacinternal.NewRule("get").Groups("").Resources("pods").Names("pod2").RuleOrDie(),
							rbacinternal.NewRule("get").Groups("apps").Resources("deployments").Names("dep2").RuleOrDie(),
						},
					},
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						Rules: []rbacinternal.PolicyRule{
							rbacinternal.NewRule("get").Groups("").Resources("pods").Names("pod3").RuleOrDie(),
							rbacinternal.NewRule("get").Groups("apps").Resources("deployments").Names("dep3").RuleOrDie(),
						},
					},
				},
				RoleBindings: []*rbacinternal.RoleBinding{
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				Roles: []*rbacinternal.Role{
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						Rules:      []rbacinternal.PolicyRule{rbacinternal.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie()},
					},
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						Rules: []rbacinternal.PolicyRule{
							rbacinternal.NewRule("get").Groups("").Resources("pods").RuleOrDie(),
							rbacinternal.NewRule("get").Groups("apps").Resources("deployments").RuleOrDie(),
						},
					},
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						Rules: []rbacinternal.PolicyRule{
							rbacinternal.NewRule("get").Groups("").Resources("pods").RuleOrDie(),
							rbacinternal.NewRule("get").Groups("apps").Resources("deployments").RuleOrDie(),
						},
					},
				},
				RoleBindings: []*rbacinternal.RoleBinding{
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				Roles: []*rbacinternal.Role{
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						Rules:      []rbacinternal.PolicyRule{rbacinternal.NewRule("get").Groups("").Resources("configmaps").Names("cm1").RuleOrDie()},
					},
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						Rules: []rbacinternal.PolicyRule{
							// TODO: improve compaction to make this a single rule referencing two names
							rbacinternal.NewRule("get").Groups("").Resources("pods").Names("pod1").RuleOrDie(),
							rbacinternal.NewRule("get").Groups("").Resources("pods").Names("pod2").RuleOrDie(),
							// TODO: improve compaction to make this a single rule referencing two names
							rbacinternal.NewRule("get").Groups("apps").Resources("deployments").Names("dep1").RuleOrDie(),
							rbacinternal.NewRule("get").Groups("apps").Resources("deployments").Names("dep2").RuleOrDie(),
						},
					},
					&rbacinternal.Role{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						Rules: []rbacinternal.PolicyRule{
							// TODO: improve compaction to make this a single rule referencing two names
							rbacinternal.NewRule("get").Groups("").Resources("pods").Names("pod1").RuleOrDie(),
							rbacinternal.NewRule("get").Groups("").Resources("pods").Names("pod3").RuleOrDie(),
							// TODO: improve compaction to make this a single rule referencing two names
							rbacinternal.NewRule("get").Groups("apps").Resources("deployments").Names("dep1").RuleOrDie(),
							rbacinternal.NewRule("get").Groups("apps").Resources("deployments").Names("dep3").RuleOrDie(),
						},
					},
				},
				RoleBindings: []*rbacinternal.RoleBinding{
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns1"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns2"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
					},
					&rbacinternal.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac", Namespace: "ns3"},
						RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "Role", APIGroup: "rbac.authorization.k8s.io"},
						Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
				ClusterRoles: []*rbacinternal.ClusterRole{&rbacinternal.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					Rules: []rbacinternal.PolicyRule{
						rbacinternal.NewRule("get", "list", "watch").Groups("").Resources("configmaps", "pods").RuleOrDie(),
						rbacinternal.NewRule("get", "list", "watch").Groups("apps").Resources("deployments").RuleOrDie(),
					},
				}},
				ClusterRoleBindings: []*rbacinternal.ClusterRoleBinding{&rbacinternal.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "audit2rbac"},
					RoleRef:    rbacinternal.RoleRef{Name: "audit2rbac", Kind: "ClusterRole", APIGroup: "rbac.authorization.k8s.io"},
					Subjects:   []rbacinternal.Subject{{Name: "bob", Kind: "User", APIGroup: "rbac.authorization.k8s.io"}},
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
