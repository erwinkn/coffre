// Package provider is the coffre provider for Terraform and OpenTofu
// (docs/design/terraform-provider.md): its configuration, how it signs in,
// and its resources, one file each.
package provider

import (
	"context"
	"os"
	"time"

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
	return func() provider.Provider {
		return &coffreProvider{version: version, env: os.Getenv, home: os.UserHomeDir, now: time.Now}
	}
}

type coffreProvider struct {
	version string
	// env reads the platform's own variables, GitHub's runner's, as the CLI does: the provider has none of its own.
	env func(string) string
	// home is the directory the CLI keeps its sessions under, `$HOME`; tests replace it.
	home func() (string, error)
	now  func() time.Time
}

type providerModel struct {
	URL     types.String `tfsdk:"url"`
	Token   types.String `tfsdk:"token"`
	OIDC    *oidcModel   `tfsdk:"oidc"`
	Session types.Bool   `tfsdk:"session"`
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
		Description: "Writes coffre secrets and configuration, and keeps no value or credential: not in state, a plan or a log. Signs in as a service account, by its token or a CI run's ID token, or as a person, by the session `coffre login` saved.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Required:    true,
				Description: "The instance's URL, such as `https://secrets.acme.example`: https, or http on loopback.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "A service account's token (`coffre_svc_…`). Give this, `oidc` or `session`.",
			},
			"oidc": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Sign in with the CI run's ID token, traded for a credential of five minutes, renewed as it runs. Give this, `token` or `session`.",
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
			"session": schema.BoolAttribute{
				Optional:    true,
				Description: "Sign in as the person whose session `coffre login <url>` saved for this url, in `~/.coffre/credentials.json`: read, never written, and kept nowhere. The only sign-in `coffre_service_account` and `coffre_trust` take. Give this, `token` or `oidc`.",
			},
		},
	}
}

// configured is what the resources are handed: the client, signed in, and how.
type configured struct {
	client *coffre.Client
	// by is how it signed in: `token`, `oidc` or `session`.
	by string
	// person is who signed in by `session`: `user:<email>`.
	person string
}

// signedIn is how a configured provider signs in, in the words of its block.
func (c *configured) signedIn() string {
	if c.by == "session" {
		return "a person (session = true)"
	}
	return "a service account (" + c.by + ")"
}

func (p *coffreProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.URL.IsUnknown() || config.Token.IsUnknown() || config.Session.IsUnknown() || (config.OIDC != nil && (config.OIDC.Service.IsUnknown() || config.OIDC.IDToken.IsUnknown())) {
		resp.Diagnostics.AddError("The provider's configuration is not known yet", "url, token, oidc and session must be known when Terraform plans: set them from variables or values known before apply.")
		return
	}
	origin, err := coffre.Origin(config.URL.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "Not an instance's URL", err.Error())
		return
	}
	token := config.Token.ValueString()
	session := config.Session.ValueBool()
	ways := 0
	for _, given := range []bool{token != "", config.OIDC != nil, session} {
		if given {
			ways++
		}
	}
	var signer coffre.Signer
	data := &configured{}
	switch {
	case ways > 1:
		resp.Diagnostics.AddError("Two ways to sign in", "Give one of token, oidc or session.")
		return
	case session:
		home, err := p.home()
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("session"), "No home directory", "session = true reads the session `coffre login` saved under your home directory, and there is none: "+err.Error())
			return
		}
		saved, err := coffre.ReadSession(coffre.CredentialsFile(home), origin, p.now())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("session"), "No session to sign in with", err.Error())
			return
		}
		signer, data.by, data.person = saved, "session", saved.Member
	case token != "":
		signer, data.by = coffre.Token(token), "token"
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
		signer, data.by = &coffre.OIDC{Service: coffre.ServiceMember(service), IDTokens: tokens}, "oidc"
	default:
		resp.Diagnostics.AddError("No way to sign in", "Give token, a service account's token; oidc, to sign in with the CI run's ID token; or session = true, to sign in as the person whose `coffre login` session is saved.")
		return
	}
	userAgent := "terraform-provider-coffre/" + p.version + " terraform/" + req.TerraformVersion
	data.client = coffre.New(origin, signer, userAgent)
	resp.ResourceData = data
	resp.DataSourceData = data
}

func (p *coffreProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newSecretResource, newEnvironmentResource, newGrantResource, newServiceAccountResource, newTrustResource}
}

func (p *coffreProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}
