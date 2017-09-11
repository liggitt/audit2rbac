# audit2rbac

## Overview

audit2rbac takes a [Kubernetes audit log](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/) and username as input, and generates [RBAC](https://kubernetes.io/docs/admin/authorization/rbac/) role and binding objects that cover all the API requests made by that user.

audit2rbac is in the nascent stages of development, and will change internal and external interfaces before a stable release.

* [Release history](CHANGELOG.md)
* [Known issues](https://github.com/liggitt/audit2rbac/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

## User Instructions

1. Obtain a Kubernetes audit log containing all the API requests you expect your user to perform
    * The log must be in JSON format (requires running an API server with `--feature-gates=AdvancedAudit=true` and a `--audit-policy-file` defined... see [documentation](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#advanced-audit) for more details)
    * `v1alpha1` or `v1beta1` audit events are supported
    * The `Metadata` log level works best to minimize log size
    * To exercise all API calls, it is sometimes necessary to grant broad access to a user or application to avoid short-circuiting code paths on failed API requests. This should be done cautiously, ideally in a development environment.
2. Identify a specific user you want to generate roles for. This can be a normal user with a username like `bob` or a service account with a username like `system:serviceaccount:my-namespace:my-service-account`.
3. Run `audit2rbac`, capturing the output
    ```sh
    audit2rbac --filename audit.log --user system:serviceaccount:my-namespace:my-user > roles.yaml

    Loading events...............................................
    Evaluating API calls...
    Generating roles...
    Complete!
    ```
4. Inspect the output to verify the generated roles/bindings:
    ```sh
    more roles.yaml 

    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      creationTimestamp: null
      labels:
        audit2rbac.liggitt.net/generated: "true"
        audit2rbac.liggitt.net/user: my-user
      name: audit2rbac:my-user
    rules:
    - apiGroups:
    ...
    ```
5. Load the generated roles/bindings:
    ```sh
    kubectl create -f roles.yaml

    clusterrole "audit2rbac:my-user" created
    clusterrolebinding "audit2rbac:my-user" created
    role "audit2rbac:my-user" created
    rolebinding "audit2rbac:my-user" created
    ```

## Developer Instructions

Requirements:
* Go 1.8+
* Glide 0.12.3+

To download, install dependencies, and build:
```sh
go get -d github.com/liggitt/audit2rbac
cd $GOPATH/src/github.com/liggitt/audit2rbac
git fetch --tags
make install-deps
make
```
