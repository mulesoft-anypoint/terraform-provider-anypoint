package anypoint

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-cty/cty"

	private_space "github.com/mulesoft-anypoint/anypoint-client-go/private_space"
)

// tgwModeFromRawConfig reports which mode a private space transit gateway
// resource is configured in. Attach mode applies when transit_gateway_id is
// non-null and non-empty in the raw config (an unknown value counts as set,
// with an empty tgwID). conflicting lists the create-mode-only attributes
// (name, resource_share_id, resource_share_account) that are non-null in the
// raw config, in that order; unknown values count as present.
func tgwModeFromRawConfig(raw cty.Value) (attach bool, tgwID string, conflicting []string) {
	if raw.IsNull() || !raw.IsKnown() || !raw.Type().IsObjectType() {
		return false, "", nil
	}
	attrs := raw.Type().AttributeTypes()
	if _, ok := attrs["transit_gateway_id"]; ok {
		v := raw.GetAttr("transit_gateway_id")
		switch {
		case v.IsNull():
		case !v.IsKnown():
			attach = true
		case v.Type() == cty.String && v.AsString() != "":
			attach = true
			tgwID = v.AsString()
		}
	}
	for _, name := range []string{"name", "resource_share_id", "resource_share_account"} {
		if _, ok := attrs[name]; !ok {
			continue
		}
		if !raw.GetAttr(name).IsNull() {
			conflicting = append(conflicting, name)
		}
	}
	return attach, tgwID, conflicting
}

// findOrgTGWByShare returns the org-level transit gateway whose
// spec.resourceShare.id equals shareID.
func findOrgTGWByShare(list []private_space.TransitGateway, shareID string) (private_space.TransitGateway, bool) {
	for _, tgw := range list {
		spec := tgw.GetSpec()
		share := spec.GetResourceShare()
		if share.GetId() == shareID {
			return tgw, true
		}
	}
	return private_space.TransitGateway{}, false
}

// tgwLiveAttachments returns the attachments of an org-level transit gateway
// that are not detached. The org list keeps "ghost" entries with status
// "detached" after a detach; an unknown or empty status counts as live.
func tgwLiveAttachments(tgw private_space.TransitGateway) []private_space.TransitGateway {
	var live []private_space.TransitGateway
	for _, att := range tgw.GetAttachments() {
		status := att.GetStatus()
		if status.GetAttachment() != "detached" {
			live = append(live, att)
		}
	}
	return live
}

// tgwShareConflictHint builds the diagnostic detail shown when a create-mode
// resource hits a resource share that an org transit gateway already uses.
func tgwShareConflictHint(tgw private_space.TransitGateway, psid string) string {
	var spaces []string
	for _, att := range tgwLiveAttachments(tgw) {
		spec := att.GetSpec()
		if n := spec.GetSpaceName(); n != "" {
			spaces = append(spaces, n)
		}
	}
	return fmt.Sprintf(
		"Transit gateway %s (%q) already uses this resource share and is attached to %s. "+
			"To attach it to private space %s, set transit_gateway_id = %q (for example a reference to the other resource's transit_gateway_id) "+
			"and remove name, resource_share_id and resource_share_account.",
		tgw.GetId(), tgw.GetName(), strings.Join(spaces, ", "), psid, tgw.GetId(),
	)
}

// tgwShareClaimedHint is the counterpart of tgwShareConflictHint when another
// create-mode resource of this provider process already owns the share, which
// the eventually consistent org list may not show yet.
// The name is omitted when empty (the org list did not show the transit
// gateway yet).
func tgwShareClaimedHint(tgwID, name, psid string) string {
	label := tgwID
	if name != "" {
		label = fmt.Sprintf("%s (%q)", tgwID, name)
	}
	return fmt.Sprintf(
		"Transit gateway %s already uses this resource share and is already used by another anypoint_private_space_transit_gateway in this apply. "+
			"To attach it to private space %s, set transit_gateway_id = %q (for example a reference to the other resource's transit_gateway_id) "+
			"and remove name, resource_share_id and resource_share_account.",
		label, psid, tgwID,
	)
}
