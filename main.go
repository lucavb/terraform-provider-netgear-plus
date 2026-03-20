package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/provider"
)

func main() {
	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/lucavb/netgear-plus",
	}

	if err := providerserver.Serve(context.Background(), provider.New, opts); err != nil {
		log.Fatal(err)
	}
}
