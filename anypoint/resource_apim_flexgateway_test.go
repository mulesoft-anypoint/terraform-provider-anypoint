package anypoint

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestApimFlexGatewaySchema_AssetVersionNotForceNew(t *testing.T) {
	if resourceApimFlexGateway().Schema["asset_version"].ForceNew {
		t.Fatal("asset_version must not be ForceNew")
	}
}

func TestApimFlexGatewaySchema_TagsDiffSuppress(t *testing.T) {
	if resourceApimFlexGateway().Schema["tags"].DiffSuppressFunc == nil {
		t.Fatal("tags must have a DiffSuppressFunc (case-insensitive)")
	}
}

func TestApimFlexGatewaySchema_AssetVersionUpdatable(t *testing.T) {
	for _, a := range getApimFlexGatewayUpdatableAttributes() {
		if a == "asset_version" {
			return
		}
	}
	t.Fatal("asset_version must be in the updatable attributes")
}

func TestNewApimFlexGatewayPostBody_DescriptionAndProvider(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, map[string]any{
		"description": "d",
		"provider_id": "p",
	})
	body := newApimFlexGatewayPostBody(d)
	if got := body.GetDescription(); got != "d" {
		t.Errorf("description = %q, want d", got)
	}
	if got := body.GetProviderId(); got != "p" {
		t.Errorf("provider_id = %q, want p", got)
	}

	empty := newApimFlexGatewayPostBody(schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, map[string]any{}))
	if empty.HasDescription() {
		t.Error("description must not be set when unset in config")
	}
}

// apimFlexGatewayDiffConfig builds a minimal raw config satisfying the Required
// attributes and blocks, overlaid with the given extras.
func apimFlexGatewayDiffConfig(assetVersion string, extra map[string]any) *terraform.ResourceConfig {
	raw := map[string]any{
		"org_id":                 "org",
		"env_id":                 "env",
		"asset_group_id":         "grp",
		"asset_id":               "asset",
		"asset_version":          assetVersion,
		"deployment_target_id":   "target",
		"deployment_target_name": "target-name",
		"upstreams": []any{
			map[string]any{"label": "u", "uri": "https://example.com"},
		},
		"routing": []any{
			map[string]any{
				"label": "r",
				"upstreams": []any{
					map[string]any{"label": "u", "weight": 100},
				},
			},
		},
	}
	for k, v := range extra {
		raw[k] = v
	}
	return terraform.NewResourceConfigRaw(raw)
}

func apimFlexGatewayDiffState(assetVersion string, extra map[string]string) *terraform.InstanceState {
	attrs := map[string]string{
		"id":                     "1",
		"org_id":                 "org",
		"env_id":                 "env",
		"asset_group_id":         "grp",
		"asset_id":               "asset",
		"asset_version":          assetVersion,
		"deployment_target_id":   "target",
		"deployment_target_name": "target-name",
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return &terraform.InstanceState{ID: "1", Attributes: attrs}
}

func TestApimFlexGatewayDiff_CaseOnlyTagsNoDiff(t *testing.T) {
	state := apimFlexGatewayDiffState("1.0.0", map[string]string{"tags.#": "2", "tags.0": "mytag", "tags.1": "qa"})
	cfg := apimFlexGatewayDiffConfig("1.0.0", map[string]any{"tags": []any{"MYTAG", "QA"}})
	diff, err := resourceApimFlexGateway().Diff(context.Background(), state, cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff == nil {
		return
	}
	for k := range diff.Attributes {
		if strings.HasPrefix(k, "tags") {
			t.Errorf("case-only tag change must not produce a diff, got %q: %#v", k, diff.Attributes[k])
		}
	}
}

func TestApimFlexGatewayDiff_CaseDuplicateTagsError(t *testing.T) {
	state := apimFlexGatewayDiffState("1.0.0", nil)
	cfg := apimFlexGatewayDiffConfig("1.0.0", map[string]any{"tags": []any{"QA", "qa"}})
	_, err := resourceApimFlexGateway().Diff(context.Background(), state, cfg, nil)
	if err == nil {
		t.Fatal("expected error for case-duplicate tags")
	}
	if !strings.Contains(err.Error(), `"QA"`) || !strings.Contains(err.Error(), `"qa"`) {
		t.Errorf("error should name both tags, got %q", err)
	}
}

func TestApimFlexGatewayDiff_MajorBumpRequiresNew(t *testing.T) {
	state := apimFlexGatewayDiffState("1.0.0", nil)
	diff, err := resourceApimFlexGateway().Diff(context.Background(), state, apimFlexGatewayDiffConfig("2.0.0", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff == nil || !diff.RequiresNew() {
		t.Errorf("major bump 1.0.0 -> 2.0.0 must require replacement, got %#v", diff)
	}
	diff, err = resourceApimFlexGateway().Diff(context.Background(), state, apimFlexGatewayDiffConfig("1.0.1", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff == nil {
		t.Fatal("expected an in-place diff for 1.0.0 -> 1.0.1")
	}
	if diff.RequiresNew() {
		t.Errorf("minor bump 1.0.0 -> 1.0.1 must update in place, got %#v", diff)
	}
}
