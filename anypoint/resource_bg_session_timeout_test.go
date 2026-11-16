package anypoint

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	org "github.com/mulesoft-anypoint/anypoint-client-go/org"
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

func TestSetBGSessionTimeout_AbsentKeepsState(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceBG().Schema, map[string]any{
		"name":            "bg",
		"owner_id":        "owner",
		"session_timeout": 60,
	})
	res := org.MasterBGDetail{}
	if err := setBGSessionTimeout(d, &res, true); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if got := d.Get("session_timeout").(int); got != 60 {
		t.Fatalf("expected session_timeout to stay 60 when absent from API, got %d", got)
	}
}

func TestSetBGSessionTimeout_PresentOverwrites(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceBG().Schema, map[string]any{
		"name":            "bg",
		"owner_id":        "owner",
		"session_timeout": 60,
	})
	res := org.MasterBGDetail{}
	res.SetSessionTimeout(120)
	if err := setBGSessionTimeout(d, &res, true); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if got := d.Get("session_timeout").(int); got != 120 {
		t.Fatalf("expected session_timeout 120, got %d", got)
	}
}

func TestSetBGSessionTimeout_DataSourceAbsentIsZero(t *testing.T) {
	d := schema.TestResourceDataRaw(t, dataSourceBG().Schema, map[string]any{})
	res := org.MasterBGDetail{}
	if err := setBGSessionTimeout(d, &res, false); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if got := d.Get("session_timeout").(int); got != 0 {
		t.Fatalf("expected session_timeout 0 when absent, got %d", got)
	}
}

func TestResourceBGSchema_SessionTimeoutOptionalComputed(t *testing.T) {
	s := resourceBG().Schema["session_timeout"]
	if !s.Optional || !s.Computed {
		t.Fatalf("expected Optional and Computed, got Optional=%v Computed=%v", s.Optional, s.Computed)
	}
	if s.DiffSuppressFunc != nil {
		t.Fatal("expected no DiffSuppressFunc")
	}
}

func TestGetBGCoreAttributes_NoSessionTimeout(t *testing.T) {
	for _, a := range getBGCoreAttributes() {
		if a == "session_timeout" {
			t.Fatal("session_timeout must not be in getBGCoreAttributes")
		}
	}
}
