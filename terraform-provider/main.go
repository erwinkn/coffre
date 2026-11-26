// The coffre provider for Terraform and OpenTofu (docs/design/terraform-provider.md).
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/erwinkn/coffre/terraform-provider/internal/provider"
)

// version is the release's, set by GoReleaser (-X main.version=...).
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers such as delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/erwinkn/coffre",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
