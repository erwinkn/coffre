// Package provider is the coffre Terraform provider: one write-only
// resource, coffre_secret (docs/design/terraform-provider.md).
package provider

import (
	"context"
	"net/http"
	"net/url"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

// Options are what a test changes: the platform's variables and the HTTP
// client. A release reads the process's own environment, for GitHub's
// variables alone.
type Options struct {
	Runner     coffre.Runner
	HTTPClient *http.Client
}

// New returns the provider's factory, for providerserver.
func New(version string, options Options) func() provider.Provider {
	if options.Runner == nil {
		options.Runner = os.Getenv
	}
	return func() provider.Provider { return &coffreProvider{version: version, options: options} }
}

type coffreProvider struct {
	version string
	options Options
}

type providerModel struct {
	URL     types.String `tfsdk:"url"`
	Service types.String `tfsdk:"service"`
	IDToken types.String `tfsdk:"id_token"`
	Token   types.String `tfsdk:"token"`
}

func (p *coffreProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "coffre"
	resp.Version = p.version
}

func (p *coffreProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Writes secrets into coffre and never reads one back. Signs in with exactly one of: `service` alone (GitHub Actions' OIDC), `service` with `id_token` (another issuer's ID token, one per phase), or `token`.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Required:    true,
				Description: "The coffre instance, by its origin: https://secrets.acme.example.",
			},
			"service": schema.StringAttribute{
				Optional:    true,
				Description: "The service account to sign in as, by OIDC: GitHub Actions' ID token, or with id_token another issuer's.",
			},
			"id_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "An ID token for service, from an ephemeral variable. Spent once: one per Terraform phase (plan -out, then apply the saved plan with another).",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "A bearer token, coffre_svc_ or coffre_pat_, from an ephemeral variable.",
			},
		},
	}
}

// ValidateConfig holds the configuration to exactly one way of signing in,
// at terraform validate, never a guess at runtime.
func (p *coffreProvider) ValidateConfig(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	given := func(value types.String) bool { return !value.IsNull() }
	if problem := signInProblem(given(config.Service), given(config.IDToken), given(config.Token)); problem != "" {
		resp.Diagnostics.AddError("coffre: how to sign in", problem)
	}
	emptyGiven(config, &resp.Diagnostics)
	if !config.URL.IsUnknown() && !config.URL.IsNull() {
		if _, problem := originOf(config.URL.ValueString()); problem != "" {
			resp.Diagnostics.AddAttributeError(path.Root("url"), "coffre: url", problem)
		}
	}
}

// signInProblem says what is wrong with the attributes given, or "".
func signInProblem(service, idToken, token bool) string {
	switch {
	case token && (service || idToken):
		return "give token alone, or service (with id_token, off GitHub Actions): not both"
	case idToken && !service:
		return "id_token is an ID token for a service account: name it in service"
	case !token && !service:
		return "sign in with service (GitHub Actions' OIDC, or with id_token another issuer's), or with token"
	}
	return ""
}

// emptyGiven fails each attribute given as "": a credential that came out
// empty (an unset variable, a failed command) must stop the run, never
// switch it to another way of signing in. Unknown values are checked again
// at Configure, once known.
func emptyGiven(config providerModel, diags *diag.Diagnostics) {
	for name, value := range map[string]types.String{"service": config.Service, "id_token": config.IDToken, "token": config.Token} {
		if !value.IsNull() && !value.IsUnknown() && value.ValueString() == "" {
			diags.AddAttributeError(path.Root(name), "coffre: "+name+" is empty",
				name+" is given but empty; leave it out, or give it a value: an empty "+name+" never falls back to another way of signing in")
		}
	}
}

// originOf reads the instance's URL as an origin: http(s), a host, no
// path but "/", no query.
func originOf(raw string) (string, string) {
	address, err := url.Parse(raw)
	if err != nil || (address.Scheme != "https" && address.Scheme != "http") || address.Host == "" {
		return "", "url is the instance's origin, https://secrets.acme.example"
	}
	if (address.Path != "" && address.Path != "/") || address.RawQuery != "" || address.Fragment != "" || address.User != nil {
		return "", "url is the instance's origin alone, https://secrets.acme.example: no path, query or credentials"
	}
	return address.Scheme + "://" + address.Host, ""
}

func (p *coffreProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.URL.IsUnknown() || config.Service.IsUnknown() || config.IDToken.IsUnknown() || config.Token.IsUnknown() {
		// Known at apply: the resources wait for it (`clientOf`).
		return
	}
	emptyGiven(config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	origin, problem := originOf(config.URL.ValueString())
	if problem != "" {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "coffre: url", problem)
		return
	}
	auth := coffre.Auth{Token: config.Token.ValueString(), Service: config.Service.ValueString(), IDToken: config.IDToken.ValueString()}
	client := coffre.New(origin, auth, p.options.Runner, p.options.HTTPClient, p.version)
	resp.ResourceData = client
}

func (p *coffreProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newSecretResource}
}

func (p *coffreProvider) DataSources(context.Context) []func() datasource.DataSource {
	// None: nothing that reads a value (decision 1).
	return nil
}
