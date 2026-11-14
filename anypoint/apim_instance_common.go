package anypoint

import (
	"context"
	"fmt"
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

// diffSuppressTagsCaseInsensitive hides case-only differences between tags.
// Anypoint lowercases tags on storage, so "QA" in config reads back as "qa".
// The list length (tags.#) is suppressed only when it is unchanged.
func diffSuppressTagsCaseInsensitive(k, oldV, newV string, d *schema.ResourceData) bool {
	if strings.HasSuffix(k, ".#") {
		return oldV == newV
	}
	return strings.EqualFold(oldV, newV)
}

// validateTagsNoCaseDuplicates rejects tags that differ only by case, because
// Anypoint lowercases tags and merges them, which would cause a permanent diff.
func validateTagsNoCaseDuplicates(tags []string) error {
	seen := make(map[string]string, len(tags))
	for _, t := range tags {
		key := strings.ToLower(t)
		if prev, ok := seen[key]; ok {
			return fmt.Errorf("tags %q and %q differ only by case; Anypoint stores tags lowercased and would merge them", prev, t)
		}
		seen[key] = t
	}
	return nil
}

// customizeDiffTagsNoCaseDuplicates runs validateTagsNoCaseDuplicates at plan
// time (the SDK has no ValidateFunc support for TypeList).
func customizeDiffTagsNoCaseDuplicates(ctx context.Context, d *schema.ResourceDiff, m any) error {
	raw, _ := d.Get("tags").([]any)
	tags := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			tags = append(tags, s)
		}
	}
	return validateTagsNoCaseDuplicates(tags)
}

// newApimInstanceCreateFollowUpPatch builds the PATCH body for attributes the
// POST endpoints silently drop (tags, deprecated). It returns nil when there is
// nothing to send.
func newApimInstanceCreateFollowUpPatch(d *schema.ResourceData) map[string]any {
	body := make(map[string]any)
	if tags, ok := d.Get("tags").([]any); ok && len(tags) > 0 {
		body["tags"] = tags
	}
	if deprecated, _ := d.Get("deprecated").(bool); deprecated {
		body["deprecated"] = true
	}
	if len(body) == 0 {
		return nil
	}
	return body
}
