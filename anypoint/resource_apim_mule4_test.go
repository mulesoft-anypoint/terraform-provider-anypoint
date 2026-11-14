package anypoint

import (
	"testing"
	"unicode"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
