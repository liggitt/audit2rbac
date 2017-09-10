package main

import (
	"fmt"

	"github.com/liggitt/audit2rbac/pkg"
)

func main() {
	fmt.Println(pkg.NewGenerator(pkg.RBACObjects{}, nil, pkg.DefaultGenerateOptions()).Generate())
}
