package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// A role's id, as coffre names one (@coffre/core's ROLE_ID).
var rolePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// A service account's name: no space, no control character, and no `:` to start (@coffre/core's SERVICE_MEMBER).
var serviceName = regexp.MustCompile(`^[^\s:\x00-\x1f\x7f][^\s\x00-\x1f\x7f]{0,249}$`)

// configuredOf is the provider's data a resource is handed, or nil before the provider is configured.
func configuredOf(req resource.ConfigureRequest) *configured {
	data, _ := req.ProviderData.(*configured)
	return data
}

// personOnly refuses a resource coffre lets only a person change when the provider signs in as a
// service account: at plan, refresh and import, before coffre is asked anything (section 9.2).
func personOnly(data *configured, resource string, diags *diag.Diagnostics) bool {
	if data == nil || data.by == "session" {
		return true
	}
	diags.AddError(resource+" is applied by a person",
		fmt.Sprintf("coffre lets only a person on their own session, or whoever runs the instance, set up service accounts and their trust, and this provider signs in as %s. "+
			"Apply %s with `session = true` in the provider block, after `coffre login <url>`, from a configuration of its own that CI does not apply.", data.signedIn(), resource))
	return false
}

// placePath holds a grant's place to `project` or `project/environment`, each a slug.
type placePath struct{}

func (placePath) Description(context.Context) string {
	return "a place: a project's slug, or project/environment"
}
func (v placePath) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func validPlace(at string) bool {
	parts := strings.Split(at, "/")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if !slugPattern.MatchString(part) {
			return false
		}
	}
	return true
}

// member holds a member to `user:<email>`, in lowercase as coffre keeps it, or `token:<name>`.
type member struct{ servicesOnly bool }

func (m member) Description(context.Context) string {
	if m.servicesOnly {
		return "a service account: token:<name>"
	}
	return "a member: user:<email>, in lowercase, or token:<name>"
}
func (m member) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }
func (m member) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if why := memberProblem(req.ConfigValue.ValueString(), m.servicesOnly); why != "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Not a member", why)
	}
}

func memberProblem(named string, servicesOnly bool) string {
	if name, ok := strings.CutPrefix(named, "token:"); ok {
		if !serviceName.MatchString(name) {
			return fmt.Sprintf("%q is not a service account's name: token:<name>, with no space in it.", named)
		}
		return ""
	}
	if servicesOnly {
		return fmt.Sprintf("%q is not a service account: name it token:<name>.", named)
	}
	email, ok := strings.CutPrefix(named, "user:")
	if !ok || !strings.Contains(email, "@") || strings.ContainsAny(email, " \t\n") || len(named) > 256 {
		return fmt.Sprintf("%q is not a member: user:<email> or token:<name>.", named)
	}
	if strings.ToLower(email) != email {
		return fmt.Sprintf("%q is not as coffre keeps it: in lowercase, %q.", named, "user:"+strings.ToLower(email))
	}
	return ""
}

func (placePath) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if at := req.ConfigValue.ValueString(); !validPlace(at) {
		resp.Diagnostics.AddAttributeError(req.Path, "Not a place", fmt.Sprintf("%q is not a place: a project's slug, such as billing, or project/environment, such as billing/prod.", at))
	}
}

type attrValue = attr.Value

// stringMap is a map of strings as Go has it; an unknown or null one is empty.
func stringMap(ctx context.Context, value types.Map, diags *diag.Diagnostics) map[string]string {
	out := map[string]string{}
	if value.IsNull() || value.IsUnknown() {
		return out
	}
	diags.Append(value.ElementsAs(ctx, &out, false)...)
	return out
}

// stringValues is a map of strings as the framework takes one.
func stringValues(in map[string]string) map[string]attr.Value {
	out := make(map[string]attr.Value, len(in))
	for key, value := range in {
		out[key] = types.StringValue(value)
	}
	return out
}
