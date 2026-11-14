package anypoint

import (
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestApimPatchValue(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want any
	}{
		{"empty string becomes nil", "", nil},
		{"non-empty string unchanged", "x", "x"},
		{"false unchanged", false, false},
		{"zero unchanged", 0, 0},
		{"empty list unchanged", []any{}, []any{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := apimPatchValue(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("apimPatchValue(%#v) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}

func TestAssetVersionMajorChanged(t *testing.T) {
	cases := []struct {
		oldV, newV string
		want       bool
	}{
		{"1.0.0", "1.0.1", false},
		{"1.0.1", "2.0.0", true},
		{"", "1.0.0", false},
		{"v1", "1.0.0", false},
	}
	for _, c := range cases {
		if got := assetVersionMajorChanged(c.oldV, c.newV); got != c.want {
			t.Errorf("assetVersionMajorChanged(%q, %q) = %v, want %v", c.oldV, c.newV, got, c.want)
		}
	}
}

func TestDiffSuppressTagsCaseInsensitive(t *testing.T) {
	cases := []struct {
		k, oldV, newV string
		want          bool
	}{
		{"tags.0", "mytag", "MYTAG", true},
		{"tags.0", "a", "b", false},
		{"tags.#", "2", "2", true},
		{"tags.#", "2", "3", false},
	}
	for _, c := range cases {
		if got := diffSuppressTagsCaseInsensitive(c.k, c.oldV, c.newV, nil); got != c.want {
			t.Errorf("diffSuppressTagsCaseInsensitive(%q,%q,%q) = %v, want %v", c.k, c.oldV, c.newV, got, c.want)
		}
	}
}

func TestValidateTagsNoCaseDuplicates(t *testing.T) {
	err := validateTagsNoCaseDuplicates([]string{"QA", "qa"})
	if err == nil {
		t.Fatal("expected error for [QA qa]")
	}
	if !strings.Contains(err.Error(), `"QA"`) || !strings.Contains(err.Error(), `"qa"`) {
		t.Errorf("error should name both tags, got %q", err)
	}
	if err := validateTagsNoCaseDuplicates([]string{"a", "b"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := validateTagsNoCaseDuplicates([]string{}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewApimInstanceCreateFollowUpPatch(t *testing.T) {
	build := func(raw map[string]any) *schema.ResourceData {
		return schema.TestResourceDataRaw(t, resourceApimMule4().Schema, raw)
	}
	if got := newApimInstanceCreateFollowUpPatch(build(map[string]any{})); got != nil {
		t.Errorf("want nil, got %#v", got)
	}
	got := newApimInstanceCreateFollowUpPatch(build(map[string]any{"tags": []any{"A"}}))
	if want := map[string]any{"tags": []any{"A"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	got = newApimInstanceCreateFollowUpPatch(build(map[string]any{"deprecated": true}))
	if want := map[string]any{"deprecated": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
