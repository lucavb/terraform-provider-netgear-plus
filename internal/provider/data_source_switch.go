package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
)

type switchDataSource struct {
	data *providerData
}

type switchDataSourceModel struct {
	ID                types.String `tfsdk:"id"`
	Model             types.String `tfsdk:"model"`
	SwitchName        types.String `tfsdk:"switch_name"`
	SerialNumber      types.String `tfsdk:"serial_number"`
	MACAddress        types.String `tfsdk:"mac_address"`
	FirmwareVersion   types.String `tfsdk:"firmware_version"`
	BootloaderVersion types.String `tfsdk:"bootloader_version"`
}

// NewSwitchDataSource returns the switch metadata data source.
func NewSwitchDataSource() datasource.DataSource {
	return &switchDataSource{}
}

func (d *switchDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_switch"
}

func (d *switchDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dschema.Schema{
		Attributes: map[string]dschema.Attribute{
			"id":                 dschema.StringAttribute{Computed: true},
			"model":              dschema.StringAttribute{Computed: true},
			"switch_name":        dschema.StringAttribute{Computed: true},
			"serial_number":      dschema.StringAttribute{Computed: true},
			"mac_address":        dschema.StringAttribute{Computed: true},
			"firmware_version":   dschema.StringAttribute{Computed: true},
			"bootloader_version": dschema.StringAttribute{Computed: true},
		},
	}
}

func (d *switchDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.data = req.ProviderData.(*providerData)
}

func (d *switchDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.data == nil {
		resp.Diagnostics.AddError("Provider not configured", "Configure the `netgear_plus` provider before reading `netgear_plus_switch`.")
		return
	}

	if err := withDriverForHost(ctx, d.data, func(driver client.Driver) error {
		facts, err := driver.ReadSwitchFacts(ctx)
		if err != nil {
			return operationError("Read switch facts failed", err)
		}

		state := switchDataSourceModel{
			ID:                types.StringValue(facts.ResourceID()),
			Model:             types.StringValue(facts.Model),
			SwitchName:        types.StringValue(facts.SwitchName),
			SerialNumber:      types.StringValue(facts.SerialNumber),
			MACAddress:        types.StringValue(facts.MACAddress),
			FirmwareVersion:   types.StringValue(facts.FirmwareVersion),
			BootloaderVersion: types.StringValue(facts.BootloaderVersion),
		}

		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return nil
	}); err != nil {
		addDriverError(&resp.Diagnostics, err)
	}
}
