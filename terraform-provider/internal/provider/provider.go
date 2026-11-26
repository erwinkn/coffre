// Package provider is the coffre provider for Terraform and OpenTofu
// (docs/design/terraform-provider.md): its configuration, how it signs in,
// and its resources, one file each.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

// New makes the provider, at its release's version.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &coffreProvider{version: version, env: os.Getenv} }
}

type coffreProvider struct {
	version string
	// env reads the platform's own variables, GitHub's runner's, as the CLI does: the provider has none of its own.
	env func(string) string
}

type providerModel struct {
	URL   types.String `tfsdk:"url"`
	Token types.String `tfsdk:"token"`
	OIDC  *oidcModel   `tfsdk:"oidc"`
}

type oidcModel struct {
	Service types.String `tfsdk:"service"`
	IDToken types.String `tfsdk:"id_token"`
}

func (p *coffreProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "coffre"
	resp.Version = p.version
}

func (p *coffreProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Writes coffre secrets, and keeps no value: not in state, a plan or a log. Signs in as a service account, by its token or a CI run's ID token.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Required:    true,
				Description: "The instance's URL, such as `https://secrets.acme.example`: https, or http on loopback.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "A service account's token (`coffre_svc_…`). Give this or `oidc`.",
			},
			"oidc": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Sign in with the CI run's ID token, traded for a credential of five minutes, renewed as it runs. Give this or `token`.",
				Attributes: map[string]schema.Attribute{
					"service": schema.StringAttribute{
						Required:    true,
						Description: "The service account, `terraform` or `token:terraform`, whose trust binding takes this run.",
					},
					"id_token": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "The run's ID token, for the instance's URL as its audience. It serves one exchange, so one run. Left out in GitHub Actions (`permissions: id-token: write`), the provider asks the runner for a fresh one each time.",
					},
				},
			},
		},
	}
}

// configured is what the resources are handed: the client, signed in.
type configured struct {
	client *coffre.Client
}

func (p *coffreProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.URL.IsUnknown() || config.Token.IsUnknown() || (config.OIDC != nil && (config.OIDC.Service.IsUnknown() || config.OIDC.IDToken.IsUnknown())) {
		resp.Diagnostics.AddError("The provider's configuration is not known yet", "url, token and oidc must be known when Terraform plans: set them from variables or values known before apply.")
		return
	}
	origin, err := coffre.Origin(config.URL.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "Not an instance's URL", err.Error())
		return
	}
	token := config.Token.ValueString()
	var signer coffre.Signer
	switch {
	case token != "" && config.OIDC != nil:
		resp.Diagnostics.AddError("Two ways to sign in", "Give token or oidc, not both.")
		return
	case token != "":
		signer = coffre.Token(token)
	case config.OIDC != nil:
		service := config.OIDC.Service.ValueString()
		if service == "" {
			resp.Diagnostics.AddAttributeError(path.Root("oidc").AtName("service"), "No service account", "oidc.service names the service account the run signs in as, such as terraform.")
			return
		}
		var tokens coffre.IDTokens
		if given := config.OIDC.IDToken.ValueString(); given != "" {
			tokens = coffre.GivenIDToken(given)
		} else if url, bearer := p.env("ACTIONS_ID_TOKEN_REQUEST_URL"), p.env("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); url != "" && bearer != "" {
			tokens = coffre.ActionsIDTokens{URL: url, Token: bearer}
		} else {
			resp.Diagnostics.AddAttributeError(path.Root("oidc"), "No ID token",
				"oidc signs in with the run's ID token, and there is none: in GitHub Actions, give the job `permissions: id-token: write`; elsewhere, set oidc.id_token to one whose audience is "+origin+".")
			return
		}
		signer = &coffre.OIDC{Service: coffre.ServiceMember(service), IDTokens: tokens}
	default:
		resp.Diagnostics.AddError("No way to sign in", "Give token, a service account's token, or oidc, to sign in with the CI run's ID token.")
		return
	}
	userAgent := "terraform-provider-coffre/" + p.version + " terraform/" + req.TerraformVersion
	data := &configured{client: coffre.New(origin, signer, userAgent)}
	resp.ResourceData = data
	resp.DataSourceData = data
}

func (p *coffreProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newSecretResource}
}

func (p *coffreProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}
