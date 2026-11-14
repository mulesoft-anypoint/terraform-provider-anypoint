package anypoint

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
