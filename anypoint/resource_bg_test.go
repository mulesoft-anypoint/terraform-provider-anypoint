package anypoint

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestSetBGParentFromAncestors_LastIsParent(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceBG().Schema, map[string]any{})

	if err := setBGParentFromAncestors(d, []string{"root", "l1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := d.Get("parent_organization_id").(string); got != "l1" {
		t.Fatalf("parent_organization_id = %q, want %q", got, "l1")
	}
}

func TestSetBGParentFromAncestors_EmptyAncestorsKeepsValue(t *testing.T) {
	for name, ancestors := range map[string][]string{"empty": {}, "nil": nil} {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, resourceBG().Schema, map[string]any{
				"parent_organization_id": "keep",
			})

			if err := setBGParentFromAncestors(d, ancestors); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := d.Get("parent_organization_id").(string); got != "keep" {
				t.Fatalf("parent_organization_id = %q, want %q", got, "keep")
			}
		})
	}
}
