package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/fastpath"
)

// ---------------------------------------------------------------------------
// netgear_plus_switch_config: read-only FASTPATH text-config backup
// (GS108Tv2/GS110TPv2-class firmware).
//
// The switch serves its startup configuration over the emweb HTTP
// channel: after a main_login.html password POST (SID cookie session),
// GET /filesystem/startup-config returns the verbatim text config.
// The firmware handler (ewsFileSetupFilesystemDoc in switchdrvr.bin)
// copies nvram:startup-config to "backup-config" and serves that copy
// as text/plain — the same file the startup-config-gs108t factory
// capture carries, including the NSDP text-config header the
// firmware validates on restore.
//
// The apply/restore side (multipart POST to
// /base/system/http_file_download.html) is a follow-up resource;
// this is the safe, read-only half that also enables drift
// diagnostics on the config-file transport.
//
// Reads REQUIRE the provider `host` and `password` attributes — the
// emweb session needs the switch's routable address and the admin
// password, not just the NSDP agent MAC.
// ---------------------------------------------------------------------------

type switchConfigDataSource struct {
	data *providerData
}

type switchConfigDataSourceModel struct {
	ID                    types.String `tfsdk:"id"`
	Content               types.String `tfsdk:"content"`
	Canonical             types.String `tfsdk:"canonical"`
	SystemDescription     types.String `tfsdk:"system_description"`
	SystemSoftwareVersion types.String `tfsdk:"system_software_version"`
}

// NewSwitchConfigDataSource returns the FASTPATH config-backup data
// source.
func NewSwitchConfigDataSource() datasource.DataSource {
	return &switchConfigDataSource{}
}

func (d *switchConfigDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_switch_config"
}

func (d *switchConfigDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dschema.Schema{
		Description:         "Downloads the FASTPATH text configuration (startup-config) of a GS108Tv2/GS110TPv2-class switch over the switch's web UI file channel. Requires the provider `host` and `password` attributes.",
		MarkdownDescription: "Downloads the FASTPATH text configuration (startup-config) of a GS108Tv2/GS110TPv2-class switch over the switch's web UI file channel. Requires the provider `host` and `password` attributes.",
		Attributes: map[string]dschema.Attribute{
			"id": dschema.StringAttribute{
				Computed:    true,
				Description: "Resource identity: `fastpath@<host>/startup-config`.",
			},
			"content": dschema.StringAttribute{
				Computed:    true,
				Description: "The verbatim text configuration file, with the NSDP magic header line intact (the firmware validates this header on restore). Note: content ALWAYS changes between successive reads, because the file carries a `!System Up Time` stamp that differs on every export — never use content for equality/drift compares.",
			},
			"canonical": dschema.StringAttribute{
				Computed:    true,
				Description: "The startup-config bytes with the `!System Up Time` stamp line excluded (the fastpath config's canonical form). This is the stable comparand: two reads that agree except for the uptime stamp have identical canonical values, while verbatim `content` always differs between reads.",
			},
			"system_description": dschema.StringAttribute{
				Computed:    true,
				Description: "From the `!System Description` annotation (e.g. \"GS108Tv2\") — the product family marker the switch compares on restore.",
			},
			"system_software_version": dschema.StringAttribute{
				Computed:    true,
				Description: "From the `!System Software Version` annotation — the firmware revision marker restore validation compares.",
			},
		},
	}
}

func (d *switchConfigDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.data = req.ProviderData.(*providerData)
}

func (d *switchConfigDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.data == nil {
		resp.Diagnostics.AddError("Provider not configured", "Configure the `netgear_plus` provider before reading `netgear_plus_switch_config`.")
		return
	}

	// This channel exists only on the FASTPATH (GS108Tv2-class) web
	// UI; the GS108Ev3 emweb build has no /filesystem file service.
	if !strings.EqualFold(strings.TrimSpace(d.data.config.Model), client.ModelGS108Tv2) {
		resp.Diagnostics.AddError(
			"Model does not support the FASTPATH config channel",
			"`netgear_plus_switch_config` reads over the FASTPATH emweb file channel and requires the provider `model` attribute to be `gs108tv2`.",
		)
		return
	}

	host := strings.TrimSpace(d.data.config.Host)
	if host == "" {
		resp.Diagnostics.AddError(
			"Config read requires the provider `host` attribute",
			"The FASTPATH config-file channel transfers over the switch's web UI (emweb), which needs the switch's routable address. Set the provider `host` attribute to the switch's management address (e.g. http://10.0.2.8 or 10.0.2.8).",
		)
		return
	}

	// Per-device lock (same mutex domain as HTTP/NSDP traffic), then
	// the login + download with the request_spacing window elapsed
	// first.
	key := d.data.deviceLockKey()
	mutex := mutexForDevice(key)
	mutex.Lock()
	defer mutex.Unlock()

	if err := waitForDeviceOperation(ctx, key, d.data.config.RequestSpacing); err != nil {
		resp.Diagnostics.AddError("Request pacing failed", err.Error())
		return
	}

	timeout := d.data.config.RequestTimeout
	if timeout <= 0 {
		timeout = 15
	}

	sess, err := fastpath.WebLogin(host, d.data.config.Password, time.Duration(timeout)*time.Second)
	if err != nil {
		resp.Diagnostics.AddError("Switch login failed", err.Error())
		return
	}

	raw, err := sess.SaveConfig()
	if err != nil {
		resp.Diagnostics.AddError(
			"Config download failed",
			fmt.Sprintf("%v\n\nThe HTTP channel performs: GET /base/system/http_file_upload.html (arming), then GET /filesystem/startup-config — the firmware copies nvram:startup-config to backup-config and serves it as text/plain.", err),
		)
		return
	}

	tc, err := fastpath.ParseTextConfig(raw)
	if err != nil {
		resp.Diagnostics.AddError("Config content invalid", err.Error())
		return
	}

	state := switchConfigDataSourceModel{
		ID:                    types.StringValue(fmt.Sprintf("fastpath@%s/startup-config", host)),
		Content:               types.StringValue(string(tc.Raw)),
		Canonical:             types.StringValue(string(tc.CanonicalBytes())),
		SystemDescription:     types.StringValue(tc.SystemDescription),
		SystemSoftwareVersion: types.StringValue(tc.SystemSoftwareVersion),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
