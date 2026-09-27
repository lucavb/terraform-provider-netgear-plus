package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/client"
	"github.com/lucavb/terraform-provider-netgear-plus/internal/client/gs108tv2"
)

// ---------------------------------------------------------------------------
// Shared gs108tv2 resource semantics: reboot_to_apply preflight + the
// staged-changes warning diagnostics. Both text-config resources
// (netgear_plus_vlan_state, netgear_plus_port_config) use these.
// ---------------------------------------------------------------------------

// rebootToApplyEnabled reports the effective reboot_to_apply plan value
// (null/unknown/false = false; the schema default false covers null).
func rebootToApplyEnabled(value types.Bool) bool {
	return !value.IsNull() && !value.IsUnknown() && value.ValueBool()
}

// preflightRebootToApply returns the typed, actionable refusals for
// reboot_to_apply, judged BEFORE any staging happens (no transport
// work):
//   - gs108ev3 and every non-gs108tv2 model: the option exists only for
//     the gs108tv2 text-config channel (the ev3 driver applies LIVE —
//     there is nothing to reboot into);
//   - gs108tv2 while the driver's reboot endpoint sentinel is still
//     unpinned (phase-0b live pinning pending): refusing here keeps the
//     staged flow untouched — nothing reaches the switch.
//
// A nil error means "proceed": either reboot_to_apply is disabled, or
// it is enabled and the driver CAN reboot (RebootAndWait is then part
// of the apply flow).
func preflightRebootToApply(data *providerData, plan types.Bool) error {
	if !rebootToApplyEnabled(plan) {
		return nil
	}

	if !data.isGS108Tv2Model() {
		return &providerOperationError{
			summary: "reboot_to_apply is a gs108tv2 option",
			detail: fmt.Sprintf(
				"`reboot_to_apply = true` only applies to model %s, whose text-config channel stages changes in the startup-config until the switch reboots. Model %s applies its configuration live over %s; there is nothing for the switch to reboot into. Remove `reboot_to_apply` from this resource.",
				client.ModelGS108Tv2, data.configModelName(), modelTransportName(data),
			),
		}
	}

	if gs108tv2.RebootEndpoint == "" {
		return &providerOperationError{
			summary: "gs108tv2: reboot endpoint is not pinned yet",
			detail:  "The gs108tv2 reboot flow awaits the FASTPATH 5.4.2.36 emweb endpoint pin (provider phase 0b, live firmware probe): the driver refuses every reboot before that so it can never brick a switch on a guessed URL, and this pre-stage refusal keeps the staged flow untouched. Set `reboot_to_apply = false` (or remove the attribute) and apply without the reboot; staged changes activate on the switch's own next reboot.",
		}
	}

	return nil
}

// configModelName returns the normalized provider model name for error
// text (empty model = the default gs108ev3).
func (d *providerData) configModelName() string {
	if d == nil {
		return ""
	}
	name := strings.ToLower(strings.TrimSpace(d.config.Model))
	if name == "" {
		name = client.ModelGS108Ev3
	}
	return name
}

// modelTransportName renders the transport family a model binds to, for
// diagnostic text.
func modelTransportName(data *providerData) string {
	switch {
	case data.isGS108Tv2Model():
		return "the FASTPATH text-config channel"
	case data.agentMAC != "":
		return "NSDP"
	default:
		return "the HTTP web-UI driver"
	}
}

// addGS108Tv2StagedWarnings reports the staged-semantics diagnostics
// after a successful text-config apply (subject, e.g. "VLAN changes").
// Warnings only when the change is still PENDING (staged without a
// Terraform-driven reboot): after a successful rebooting apply the
// change is active, not pending.
func addGS108Tv2StagedWarnings(diags *diag.Diagnostics, outcome gs108tv2.ApplyOutcome, subject string, pending bool) {
	if !outcome.Staged || !pending {
		return
	}

	diags.AddWarning(
		fmt.Sprintf("gs108tv2: %s are staged for the next reboot", subject),
		"The configuration was written to the switch's startup-config and verified there, but the running configuration is unchanged until the switch reboots. Reboot the switch for the changes to take effect (or set `reboot_to_apply = true` on this resource, once the gs108tv2 reboot endpoint is pinned).",
	)
	if outcome.CanonicalDiverged {
		diags.AddWarning(
			"gs108tv2: the switch rewrote the staged configuration",
			"The staged startup-config decodes to the desired state and matches structurally, but the switch re-serialized the file through its own normalizer: the canonical bytes (uptime line excluded) differ from the uploaded bytes. No action is needed; note this when comparing config-backup fingerprints.",
		)
	}
}
