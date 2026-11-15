package anypoint

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestSetTeamParentFromAncestors_LastIsParent(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceTeam().Schema, map[string]any{})

	if err := setTeamParentFromAncestors(d, []string{"root_team", "t1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := d.Get("parent_team_id").(string); got != "t1" {
		t.Fatalf("parent_team_id = %q, want %q", got, "t1")
	}
}

func TestSetTeamParentFromAncestors_EmptyAncestorsKeepsValue(t *testing.T) {
	for name, ancestors := range map[string][]string{"empty": {}, "nil": nil} {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, resourceTeam().Schema, map[string]any{
				"parent_team_id": "keep",
			})

			if err := setTeamParentFromAncestors(d, ancestors); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := d.Get("parent_team_id").(string); got != "keep" {
				t.Fatalf("parent_team_id = %q, want %q", got, "keep")
			}
		})
	}
}
