package anypoint

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestNewBGPostBody_CreateSubOrgs(t *testing.T) {
	cases := []struct {
		name string
		cfg  any
		want bool
	}{
		{name: "config true", cfg: true, want: true},
		{name: "unset uses default", cfg: nil, want: true},
		{name: "config false", cfg: false, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := map[string]any{
				"name":                   "bg",
				"owner_id":               "owner",
				"parent_organization_id": "parent",
			}
			if tc.cfg != nil {
				raw["entitlements_createsuborgs"] = tc.cfg
			}
			d := schema.TestResourceDataRaw(t, resourceBG().Schema, raw)
			b, err := json.Marshal(newBGPostBody(d))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got struct {
				Entitlements struct {
					CreateSubOrgs *bool `json:"createSubOrgs"`
				} `json:"entitlements"`
			}
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Entitlements.CreateSubOrgs == nil {
				t.Fatalf("createSubOrgs missing from POST body: %s", b)
			}
			if *got.Entitlements.CreateSubOrgs != tc.want {
				t.Fatalf("createSubOrgs = %v, want %v", *got.Entitlements.CreateSubOrgs, tc.want)
			}
		})
	}
}

// Existing state must keep diffing the same way: a false value in state is
// moved to the default (true) when the attribute is unset, and a true value
// in state with the attribute unset plans no change.
func TestResourceBGDiff_CreateSubOrgsExistingState(t *testing.T) {
	cases := []struct {
		name     string
		state    string
		wantDiff bool
	}{
		{name: "state false, unset", state: "false", wantDiff: true},
		{name: "state true, unset", state: "true", wantDiff: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := resourceBG()
			state := &terraform.InstanceState{
				ID: "bg-id",
				Attributes: map[string]string{
					"id":                         "bg-id",
					"name":                       "bg",
					"owner_id":                   "owner",
					"parent_organization_id":     "parent",
					"entitlements_createsuborgs": tc.state,
				},
			}
			cfg := terraform.NewResourceConfigRaw(map[string]any{
				"name":                   "bg",
				"owner_id":               "owner",
				"parent_organization_id": "parent",
			})
			diff, err := r.Diff(context.Background(), state, cfg, nil)
			if err != nil {
				t.Fatalf("diff: %v", err)
			}
			var attr *terraform.ResourceAttrDiff
			if diff != nil {
				attr = diff.Attributes["entitlements_createsuborgs"]
			}
			if tc.wantDiff {
				if attr == nil || attr.Old != "false" || attr.New != "true" {
					t.Fatalf("expected false -> true diff, got %+v", attr)
				}
			} else if attr != nil && attr.Old != attr.New {
				t.Fatalf("expected no diff, got %+v", attr)
			}
		})
	}
}
