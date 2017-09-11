#!/bin/bash

version=$($(dirname "${BASH_SOURCE}")/print-version.sh)

echo "-ldflags \"-X github.com/liggitt/audit2rbac/pkg.Version=${version}\""
