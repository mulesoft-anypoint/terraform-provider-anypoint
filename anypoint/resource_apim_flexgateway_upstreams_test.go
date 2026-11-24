package anypoint

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// apimFlexGatewayUpstreamsRaw builds a raw config whose upstreams are given as
// users write them, without id.
func apimFlexGatewayUpstreamsRaw(ups ...map[string]any) map[string]any {
	raw := apimFlexGatewayBaseRaw("1.0.0")
	list := make([]any, 0, len(ups))
	for _, u := range ups {
		list = append(list, u)
	}
	raw["upstreams"] = list
	return raw
}

func upstreamLabels(items []any) []string {
	labels := make([]string, 0, len(items))
	for _, item := range items {
		labels = append(labels, item.(map[string]any)["label"].(string))
	}
	return labels
}

func TestCalcUpstreamsDiff(t *testing.T) {
	u := map[string]any{"label": "u", "uri": "https://u.example"}
	v := map[string]any{"label": "v", "uri": "https://v.example"}
	w := map[string]any{"label": "w", "uri": "https://w.example"}
	oldU := map[string]any{"id": "a", "label": "u", "uri": "https://u.example"}
	oldV := map[string]any{"id": "b", "label": "v", "uri": "https://v.example"}

	tests := []struct {
		name         string
		old          []any
		new          map[string]any
		wantCreate   []string
		wantUpdateID []string
		wantDeleteID []string
	}{
		{
			name:       "add",
			old:        []any{oldU},
			new:        apimFlexGatewayUpstreamsRaw(u, v),
			wantCreate: []string{"v"},
		},
		{
			name:       "add two",
			old:        []any{oldU},
			new:        apimFlexGatewayUpstreamsRaw(u, v, w),
			wantCreate: []string{"v", "w"},
		},
		{
			name:         "edit",
			old:          []any{oldU},
			new:          apimFlexGatewayUpstreamsRaw(map[string]any{"label": "u", "uri": "https://changed.example"}),
			wantUpdateID: []string{"a"},
		},
		{
			name:         "remove",
			old:          []any{oldU, oldV},
			new:          apimFlexGatewayUpstreamsRaw(u),
			wantDeleteID: []string{"b"},
		},
		{
			name: "no change",
			old:  []any{oldU},
			new:  apimFlexGatewayUpstreamsRaw(u),
		},
	}
	ids := func(items []any) []string {
		out := make([]string, 0, len(items))
		for _, item := range items {
			out = append(out, item.(map[string]any)["id"].(string))
		}
		return out
	}
	equal := func(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := apimFlexGatewayUpstreamChangeData(t, tt.old, tt.new)
			tocreate, toupdate, todelete := calcUpstreamsDiff(d)
			if got := upstreamLabels(tocreate); !equal(got, tt.wantCreate) {
				t.Errorf("tocreate labels = %v, want %v", got, tt.wantCreate)
			}
			if got := ids(toupdate); !equal(got, tt.wantUpdateID) {
				t.Errorf("toupdate ids = %v, want %v", got, tt.wantUpdateID)
			}
			if got := ids(todelete); !equal(got, tt.wantDeleteID) {
				t.Errorf("todelete ids = %v, want %v", got, tt.wantDeleteID)
			}
		})
	}
}

// An upstream added to an existing instance must reach the platform as a POST.
func TestApimFlexGatewayUpdate_AddedUpstreamIsPosted(t *testing.T) {
	var mu sync.Mutex
	var posts []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/apis/1/upstreams") {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			posts = append(posts, r.URL.Path+" "+string(b))
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{}"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	d := apimFlexGatewayUpstreamChangeData(t,
		[]any{map[string]any{"id": "a", "label": "u", "uri": "https://u.example"}},
		apimFlexGatewayUpstreamsRaw(
			map[string]any{"label": "u", "uri": "https://u.example"},
			map[string]any{"label": "v", "uri": "https://v.example"},
		))
	// later calls are expected to hit the 404 handler; only the POST matters here
	_ = resourceApimFlexGatewayUpdate(context.Background(), d, apimFlexGatewayTestMeta(ts.URL))

	mu.Lock()
	defer mu.Unlock()
	if len(posts) != 1 {
		t.Fatalf("expected exactly one upstream POST, got %d: %v", len(posts), posts)
	}
	path, body, _ := strings.Cut(posts[0], " ")
	if !strings.HasPrefix(path, "/organizations/") {
		t.Errorf("unexpected path %q", path)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("invalid POST body %q: %v", body, err)
	}
	if got["label"] != "v" || got["uri"] != "https://v.example" {
		t.Errorf("unexpected POST body %v", got)
	}
}
