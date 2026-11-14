package anypoint

import (
	"reflect"
	"testing"
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
