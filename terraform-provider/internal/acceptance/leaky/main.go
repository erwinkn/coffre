// terraform-provider-leaky: a provider that does what no value source may
// (section 7, guarantee 1), keeping a write-only value in its private
// data, base64 inside JSON: what the acceptance tests' leak check must
// catch first. A test fixture only; never built into a release.
//
// mode "apply" keeps it from create on. mode "refresh" keeps it only in
// what a refresh reads (from side_file, where create left it), and clears
// it in every plan and apply: a leak found only in a saved plan's
// embedded state snapshots.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	pschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func main() {
	if err := providerserver.Serve(context.Background(), func() provider.Provider { return leakyProvider{} }, providerserver.ServeOpts{Address: "registry.terraform.io/erwinkn/leaky"}); err != nil {
		log.Fatal(err)
	}
}

type leakyProvider struct{}

func (leakyProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "leaky"
}
func (leakyProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = pschema.Schema{}
}
func (leakyProvider) Configure(context.Context, provider.ConfigureRequest, *provider.ConfigureResponse) {
}
func (leakyProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{func() resource.Resource { return &secret{} }}
}
func (leakyProvider) DataSources(context.Context) []func() datasource.DataSource { return nil }

type secret struct{}

type model struct {
	ID       types.String `tfsdk:"id"`
	Mode     types.String `tfsdk:"mode"`
	SideFile types.String `tfsdk:"side_file"`
	Revision types.String `tfsdk:"revision"`
	ValueWO  types.String `tfsdk:"value_wo"`
}

func (*secret) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (*secret) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Attributes: map[string]schema.Attribute{
		"id":        schema.StringAttribute{Computed: true},
		"mode":      schema.StringAttribute{Required: true},
		"side_file": schema.StringAttribute{Required: true},
		"revision":  schema.StringAttribute{Required: true},
		"value_wo":  schema.StringAttribute{Required: true, WriteOnly: true, Sensitive: true},
	}}
}

// hide is the value as the leak keeps it: base64, inside JSON.
func hide(value string) []byte {
	raw, _ := json.Marshal(map[string]string{"kept": base64.StdEncoding.EncodeToString([]byte(value))})
	return raw
}

func (*secret) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var value types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("value_wo"), &value)...)
	plan.ID, plan.ValueWO = types.StringValue("leaky"), types.StringNull()
	if plan.Mode.ValueString() == "apply" {
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, "hidden", hide(value.ValueString()))...)
	} else if err := os.WriteFile(plan.SideFile.ValueString(), []byte(value.ValueString()), 0o600); err != nil {
		resp.Diagnostics.AddError("side file", err.Error())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (*secret) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if state.Mode.ValueString() == "refresh" {
		if value, err := os.ReadFile(state.SideFile.ValueString()); err == nil {
			resp.Diagnostics.Append(resp.Private.SetKey(ctx, "hidden", hide(string(value)))...)
		}
	}
}

func (*secret) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	plan.ID, plan.ValueWO = types.StringValue("leaky"), types.StringNull()
	if plan.Mode.ValueString() == "refresh" {
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, "hidden", nil)...)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (*secret) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {}

// ModifyPlan clears the refresh's leak from every plan.
func (*secret) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}
	var state model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if state.Mode.ValueString() == "refresh" {
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, "hidden", nil)...)
	}
}
