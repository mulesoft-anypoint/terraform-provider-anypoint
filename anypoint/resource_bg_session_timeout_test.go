package anypoint

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestNewBGPutBody_OmitsZeroSessionTimeout(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceBG().Schema, map[string]any{
		"name":     "bg",
		"owner_id": "owner",
	})
	body := newBGPutBody(d)
	if body.SessionTimeout != nil {
		t.Fatalf("expected SessionTimeout to be nil when unset, got %d", *body.SessionTimeout)
	}
}

func TestNewBGPutBody_KeepsSessionTimeout(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceBG().Schema, map[string]any{
		"name":            "bg",
		"owner_id":        "owner",
		"session_timeout": 60,
	})
	body := newBGPutBody(d)
	if body.SessionTimeout == nil || *body.SessionTimeout != 60 {
		t.Fatalf("expected SessionTimeout 60, got %v", body.SessionTimeout)
	}
}
