// terraform-provider-coffre: writes secrets into coffre, never reads one
// back (docs/design/terraform-provider.md).
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/erwinkn/coffre/terraform-provider/internal/provider"
)

// version is set by the release build (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers such as delve")
	flag.Parse()
	// The address a debug session reattaches by. A configuration names the provider by its own source address, which
	// Terraform's CLI configuration (dev_overrides, a mirror) maps to this binary; the registry namespace is decided at publishing.
	err := providerserver.Serve(context.Background(), provider.New(version, provider.Options{}), providerserver.ServeOpts{
		Address: "registry.terraform.io/erwinkn/coffre",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
