package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type vlanStateDataSource struct {
	data *providerData
}

type vlanStateDataSourceModel struct {
	ID    types.String         `tfsdk:"id"`
	VLANs []vlanAttributeModel `tfsdk:"vlan"`
	PVIDs types.Map            `tfsdk:"pvids"`
}

// NewVLANStateDataSource returns the VLAN state data source.
func NewVLANStateDataSource() datasource.DataSource {
	return &vlanStateDataSource{}
}

func (d *vlanStateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vlan_state"
}

func (d *vlanStateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dschema.Schema{
		Attributes: map[string]dschema.Attribute{
			"id": dschema.StringAttribute{Computed: true},
			"pvids": dschema.MapAttribute{
				Computed:    true,
				ElementType: types.Int64Type,
			},
			"vlan": dschema.ListNestedAttribute{
				Computed: true,
				NestedObject: dschema.NestedAttributeObject{
					Attributes: map[string]dschema.Attribute{
						"id": dschema.Int64Attribute{Computed: true},
						"ports": dschema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
		},
	}
}

func (d *vlanStateDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.data = req.ProviderData.(*providerData)
}

func (d *vlanStateDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.data == nil {
		resp.Diagnostics.AddError("Provider not configured", "Configure the `netgear_plus` provider before reading `netgear_plus_vlan_state`.")
		return
	}

	if err := withSwitchTransport(ctx, d.data, func(transport switchTransport) error {
		// The ID follows the transport's identity convention
		// (gs108ev3@<host> over HTTP, nsdp@<agent MAC> over NSDP);
		// switching transports changes the ID. See
		// switchTransport.ResourceID.
		dataState, err := readVLANStateDataSourceState(ctx, transport, transport.ResourceID())
		if err != nil {
			return err
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &dataState)...)
		return nil
	}); err != nil {
		addNSDPOperationError(&resp.Diagnostics, err)
	}
}

func readVLANStateDataSourceState(ctx context.Context, transport vlanStateTransport, resourceID string) (vlanStateDataSourceModel, error) {
	state, err := transport.ReadVLANState(ctx)
	if err != nil {
		return vlanStateDataSourceModel{}, operationError("Read VLAN state failed", err)
	}

	vlans, pvids, err := flattenVLANState(ctx, state)
	if err != nil {
		return vlanStateDataSourceModel{}, operationError("Flatten VLAN state failed", err)
	}

	return vlanStateDataSourceModel{
		ID:    types.StringValue(resourceID),
		VLANs: vlans,
		PVIDs: pvids,
	}, nil
}
