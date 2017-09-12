# audit2rbac

## Overview

audit2rbac takes a [Kubernetes audit log](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/) and username as input, and generates [RBAC](https://kubernetes.io/docs/admin/authorization/rbac/) role and binding objects that cover all the API requests made by that user.

audit2rbac is in the nascent stages of development, and will change internal and external interfaces before a stable release.

* [Releases](https://github.com/liggitt/audit2rbac/releases)
* [Known issues](https://github.com/liggitt/audit2rbac/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

## User Instructions

1. Obtain a Kubernetes audit log containing all the API requests you expect your user to perform:
    * The log must be in JSON format. This requires running an API server with `--feature-gates=AdvancedAudit=true` and an `--audit-policy-file` defined. See [documentation](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#advanced-audit) for more details.
    * `v1alpha1` or `v1beta1` audit events are supported.
    * The `Metadata` log level works best to minimize log size.
    * To exercise all API calls, it is sometimes necessary to grant broad access to a user or application to avoid short-circuiting code paths on failed API requests. This should be done cautiously, ideally in a development environment.
    * A [sample log](testdata/demo.log) containing requests from `alice`, `bob`, and the service account `ns1:sa1` is available.
2. Identify a specific user you want to scan for audit events for and generate roles and role bindings for:
    * Specify a normal user with `--user <username>`
    * Specify a service account with `--serviceaccount <namespace>:<name>`
3. Run `audit2rbac`, capturing the output:
    ```sh
    audit2rbac -f https://git.io/v51iG --user alice             > alice-roles.yaml
    audit2rbac -f https://git.io/v51iG --user bob               > bob-roles.yaml
    audit2rbac -f https://git.io/v51iG --serviceaccount ns1:sa1 > sa1-roles.yaml
    ```
4. Inspect the output to verify the generated roles/bindings:
    ```sh
    more alice-roles.yaml
    ```

    ```yaml
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      creationTimestamp: null
      labels:
        audit2rbac.liggitt.net/generated: "true"
        audit2rbac.liggitt.net/user: alice
      name: audit2rbac:alice
      namespace: ns1
    rules:
    - apiGroups:
      - ""
      resources:
      - configmaps
      verbs:
      - get
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - pods
      verbs:
      - get
      - list
      - watch
    - apiGroups:
      - ""
      resources:
      - secrets
      verbs:
      - get
      - list
      - watch
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      creationTimestamp: null
      labels:
        audit2rbac.liggitt.net/generated: "true"
        audit2rbac.liggitt.net/user: alice
      name: audit2rbac:alice
      namespace: ns1
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: Role
      name: audit2rbac:alice
    subjects:
    - apiGroup: rbac.authorization.k8s.io
      kind: User
      name: alice
    ```
5. Load the generated roles/bindings:
    ```sh
    kubectl create -f roles.yaml

    role "audit2rbac:alice" created
    rolebinding "audit2rbac:alice" created
    ```

## Developer Instructions

Requirements:
* Go 1.8+
* Glide 0.12.3+

To build and install from source:
```sh
go get -d github.com/liggitt/audit2rbac
cd $GOPATH/src/github.com/liggitt/audit2rbac
git fetch --tags
make install-deps
make install
```
