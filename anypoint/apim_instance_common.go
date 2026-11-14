package anypoint

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// apimPatchValue maps an empty string to nil so that the API clears the field
// (the API rejects "" for some attributes but accepts null). Every other value
// (including false, 0 and empty lists) is returned unchanged.
func apimPatchValue(v any) any {
	if s, ok := v.(string); ok && s == "" {
		return nil
	}
	return v
}

// assetVersionMajorChanged reports whether the major segment (before the first
// ".") differs between the two versions. When either side is empty or not a
// dotted version, it returns false and lets the API decide.
func assetVersionMajorChanged(oldV, newV string) bool {
	oldMajor, ok := assetVersionMajor(oldV)
	if !ok {
		return false
	}
	newMajor, ok := assetVersionMajor(newV)
	if !ok {
		return false
	}
	return oldMajor != newMajor
}

// assetVersionMajor returns the numeric segment before the first ".".
func assetVersionMajor(v string) (string, bool) {
	major, _, found := strings.Cut(v, ".")
	if !found || major == "" {
		return "", false
	}
	for _, r := range major {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return major, true
}

// customizeDiffAssetVersionMajor forces replacement when asset_version moves to
// another major version, which the API refuses to update in place.
func customizeDiffAssetVersionMajor(ctx context.Context, d *schema.ResourceDiff, m any) error {
	if !d.HasChange("asset_version") {
		return nil
	}
	oldV, newV := d.GetChange("asset_version")
	o, _ := oldV.(string)
	n, _ := newV.(string)
	if assetVersionMajorChanged(o, n) {
		return d.ForceNew("asset_version")
	}
	return nil
}
