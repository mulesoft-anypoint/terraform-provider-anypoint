package anypoint

import (
	"context"
	"strings"
	"testing"
	"unicode"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func newApimMule4TestData(t *testing.T) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, resourceApimMule4().Schema, map[string]any{
		"instance_label": "label",
		"description":    "desc",
		"tags":           []any{"a"},
		"asset_version":  "1.0.1",
		"endpoint_uri":   "https://example.com/api",
	})
}

func TestNewApimMule4PatchBody_LowerCamelKeys(t *testing.T) {
	body := newApimMule4PatchBody(newApimMule4TestData(t))
	for _, k := range []string{"instanceLabel", "description", "tags", "assetVersion"} {
		if _, ok := body[k]; !ok {
			t.Errorf("expected key %q in body, got %#v", k, body)
		}
	}
	for k := range body {
		if unicode.IsUpper([]rune(k)[0]) {
			t.Errorf("key %q starts with an uppercase letter", k)
		}
	}
}

func TestNewApimMule4PatchBody_EndpointUsesMule4List(t *testing.T) {
	body := newApimMule4PatchBody(newApimMule4TestData(t))
	endpoint, ok := body["endpoint"].(map[string]any)
	if !ok {
		t.Fatalf("expected endpoint map in body, got %#v", body)
	}
	if got := endpoint["uri"]; got != "https://example.com/api" {
		t.Errorf("endpoint.uri = %#v, want https://example.com/api", got)
	}
}

func TestApimMule4Schema_AssetVersionNotForceNew(t *testing.T) {
	if resourceApimMule4().Schema["asset_version"].ForceNew {
		t.Fatal("asset_version must not be ForceNew")
	}
}

func TestNewApimMule4PostBody_DescriptionAndProvider(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceApimMule4().Schema, map[string]any{
		"description": "d",
		"provider_id": "p",
	})
	body := newApimMule4PostBody(d)
	if got := body.GetDescription(); got != "d" {
		t.Errorf("description = %q, want d", got)
	}
	if got := body.GetProviderId(); got != "p" {
		t.Errorf("provider_id = %q, want p", got)
	}

	empty := newApimMule4PostBody(schema.TestResourceDataRaw(t, resourceApimMule4().Schema, map[string]any{}))
	if empty.HasDescription() {
		t.Error("description must not be set when unset in config")
	}
}

func TestNewApimMule4PatchBody_NestedEndpointKeys(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceApimMule4().Schema, map[string]any{
		"endpoint_proxy_uri":       "http://0.0.0.0:8081/",
		"endpoint_deployment_type": "CH",
	})
	body := newApimMule4PatchBody(d)
	endpoint, ok := body["endpoint"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested endpoint map in body, got %#v", body)
	}
	if got := endpoint["proxyUri"]; got != "http://0.0.0.0:8081/" {
		t.Errorf("endpoint.proxyUri = %#v, want http://0.0.0.0:8081/", got)
	}
	if got := endpoint["deploymentType"]; got != "CH" {
		t.Errorf("endpoint.deploymentType = %#v, want CH", got)
	}
}

// apimMule4DiffConfig builds a minimal raw config satisfying the Required
// attributes, overlaid with the given extras.
func apimMule4DiffConfig(assetVersion string, extra map[string]any) *terraform.ResourceConfig {
	raw := map[string]any{
		"org_id":         "org",
		"env_id":         "env",
		"asset_group_id": "grp",
		"asset_id":       "asset",
		"asset_version":  assetVersion,
	}
	for k, v := range extra {
		raw[k] = v
	}
	return terraform.NewResourceConfigRaw(raw)
}

func apimMule4DiffState(assetVersion string, extra map[string]string) *terraform.InstanceState {
	attrs := map[string]string{
		"id":             "1",
		"org_id":         "org",
		"env_id":         "env",
		"asset_group_id": "grp",
		"asset_id":       "asset",
		"asset_version":  assetVersion,
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return &terraform.InstanceState{ID: "1", Attributes: attrs}
}

func TestApimMule4Diff_CaseOnlyTagsNoDiff(t *testing.T) {
	state := apimMule4DiffState("1.0.0", map[string]string{"tags.#": "2", "tags.0": "mytag", "tags.1": "qa"})
	cfg := apimMule4DiffConfig("1.0.0", map[string]any{"tags": []any{"MYTAG", "QA"}})
	diff, err := resourceApimMule4().Diff(context.Background(), state, cfg, nil)
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

func TestApimMule4Diff_CaseDuplicateTagsError(t *testing.T) {
	state := apimMule4DiffState("1.0.0", nil)
	cfg := apimMule4DiffConfig("1.0.0", map[string]any{"tags": []any{"QA", "qa"}})
	_, err := resourceApimMule4().Diff(context.Background(), state, cfg, nil)
	if err == nil {
		t.Fatal("expected error for case-duplicate tags")
	}
	if !strings.Contains(err.Error(), `"QA"`) || !strings.Contains(err.Error(), `"qa"`) {
		t.Errorf("error should name both tags, got %q", err)
	}
}

func TestApimMule4Diff_MajorBumpRequiresNew(t *testing.T) {
	state := apimMule4DiffState("1.0.0", nil)
	diff, err := resourceApimMule4().Diff(context.Background(), state, apimMule4DiffConfig("2.0.0", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff == nil || !diff.RequiresNew() {
		t.Errorf("major bump 1.0.0 -> 2.0.0 must require replacement, got %#v", diff)
	}
	diff, err = resourceApimMule4().Diff(context.Background(), state, apimMule4DiffConfig("1.0.1", nil), nil)
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
