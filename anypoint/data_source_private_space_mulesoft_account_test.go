package anypoint

import "testing"

func TestUnquoteJSONString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"json quoted", "\"874183964486\"", "874183964486"},
		{"already plain", "874183964486", "874183964486"},
		{"padded quoted", " \"x\" ", "x"},
		{"empty", "", ""},
		{"quoted leading zero", "\"0123\"", "0123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unquoteJSONString(tc.in); got != tc.want {
				t.Fatalf("unquoteJSONString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
