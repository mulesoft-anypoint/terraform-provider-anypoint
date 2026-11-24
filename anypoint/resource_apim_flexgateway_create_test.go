package anypoint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	flexCreateInstPath     = "/xapi/v1/organizations/org/environments/env/apis"
	flexCreateInstXapiPath = "/xapi/v1/organizations/org/environments/env/apis/1"
	flexCreateUpPath       = "/organizations/org/environments/env/apis/1/upstreams"
)

type flexCreateCall struct {
	Method string
	Path   string
	Body   map[string]any
}

func (c flexCreateCall) String() string { return c.Method + " " + c.Path }

// flexCreateServer fakes the Anypoint API for Create. It records the mutating
// calls (POST/PATCH/DELETE; query strings ignored) and keeps the upstream list
// stateful. withDefault models an instance POST that also creates a default
// upstream (label null); without it the list is empty until the first upstream
// POST, as observed live in the #206 spike (endpoint_uri is computed-only, so
// the provider never sends it).
type flexCreateServer struct {
	*httptest.Server
	mu           sync.Mutex
	calls        []flexCreateCall
	upstreams    []map[string]any
	nextID       int
	failRedeploy bool
}

func newFlexCreateServer(t *testing.T, withDefault bool, failRedeploy bool) *flexCreateServer {
	t.Helper()
	s := &flexCreateServer{nextID: 1, failRedeploy: failRedeploy}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		var body map[string]any
		if r.Method != http.MethodGet {
			raw, _ := io.ReadAll(r.Body)
			if len(raw) > 0 {
				_ = json.Unmarshal(raw, &body)
			}
			s.calls = append(s.calls, flexCreateCall{Method: r.Method, Path: path, Body: body})
		}
		switch {
		case r.Method == http.MethodPost && path == flexCreateInstPath:
			if withDefault {
				s.upstreams = append(s.upstreams, map[string]any{"id": "d", "label": nil, "uri": "https://placeholder.example"})
			}
			_, _ = w.Write([]byte(`{"id":1}`))
		case r.Method == http.MethodPost && path == flexCreateUpPath:
			id := fmt.Sprintf("u%d", s.nextID)
			s.nextID++
			s.upstreams = append(s.upstreams, map[string]any{"id": id, "label": body["label"], "uri": body["uri"]})
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && path == flexCreateUpPath:
			out := map[string]any{"upstreams": append([]map[string]any{}, s.upstreams...), "total": len(s.upstreams)}
			if len(s.upstreams) == 0 {
				out["upstreams"] = []any{}
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodDelete && strings.HasPrefix(path, flexCreateUpPath+"/"):
			id := strings.TrimPrefix(path, flexCreateUpPath+"/")
			kept := s.upstreams[:0:0]
			for _, u := range s.upstreams {
				if u["id"] != id {
					kept = append(kept, u)
				}
			}
			s.upstreams = kept
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch && path == flexCreateInstXapiPath:
			if _, isRedeploy := body["deployment"]; isRedeploy && s.failRedeploy {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"deployment rejected"}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"id":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *flexCreateServer) sequence() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	for i, c := range s.calls {
		out[i] = c.String()
	}
	return out
}

func (s *flexCreateServer) last() flexCreateCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[len(s.calls)-1]
}

func TestNewApimFlexGatewayRedeployBody(t *testing.T) {
	raw := apimFlexGatewayRawWith("1.0.0", map[string]any{
		"deployment_gateway_version": "1.14.4",
		"deployment_overwrite":       true,
		"description":                "desc",
	})
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, raw)
	got := apimPatchJSON(t, newApimFlexGatewayRedeployBody(d))

	if len(got) != 1 {
		t.Fatalf("redeploy body must carry only the deployment key, got %#v", got)
	}
	assertNoEndpoint(t, got)
	want := map[string]any{
		"environmentId":  "env",
		"type":           "HY",
		"expectedStatus": "deployed",
		"overwrite":      true,
		"targetId":       "target",
		"targetName":     "target-name",
		"gatewayVersion": "1.14.4",
	}
	dep, ok := got["deployment"].(map[string]any)
	if !ok {
		t.Fatalf("deployment must be an object, got %#v", got["deployment"])
	}
	if !reflect.DeepEqual(dep, want) {
		t.Errorf("deployment mismatch:\n got  %#v\n want %#v", dep, want)
	}
}

func TestApimFlexGatewayCreate_CallOrder(t *testing.T) {
	noRouting := func() map[string]any {
		raw := apimFlexGatewayBaseRaw("1.0.0")
		delete(raw, "routing")
		return raw
	}
	tests := []struct {
		name        string
		raw         map[string]any
		withDefault bool
		want        []string
	}{
		{
			name: "routed",
			raw:  apimFlexGatewayBaseRaw("1.0.0"),
			want: []string{
				"POST " + flexCreateInstPath,
				"POST " + flexCreateUpPath,
				"PATCH " + flexCreateInstXapiPath, // routing
				"PATCH " + flexCreateInstXapiPath, // redeploy
			},
		},
		{
			name: "no routing",
			raw:  noRouting(),
			want: []string{
				"POST " + flexCreateInstPath,
				"POST " + flexCreateUpPath,
				"PATCH " + flexCreateInstXapiPath, // redeploy
			},
		},
		{
			name:        "default upstream present, deleted before redeploy",
			raw:         apimFlexGatewayBaseRaw("1.0.0"),
			withDefault: true,
			want: []string{
				"POST " + flexCreateInstPath,
				"POST " + flexCreateUpPath,
				"PATCH " + flexCreateInstXapiPath, // routing
				"DELETE " + flexCreateUpPath + "/d",
				"PATCH " + flexCreateInstXapiPath, // redeploy
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFlexCreateServer(t, tc.withDefault, false)
			d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, tc.raw)
			wantBody := apimPatchJSON(t, newApimFlexGatewayRedeployBody(d))

			diags := resourceApimFlexGatewayCreate(context.Background(), d, apimFlexGatewayTestMeta(srv.URL))
			if diags.HasError() {
				t.Fatalf("unexpected error diags: %s", diagsText(diags))
			}
			if got := srv.sequence(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mutating call sequence mismatch:\n got  %v\n want %v", got, tc.want)
			}
			last := srv.last()
			if !reflect.DeepEqual(last.Body, wantBody) {
				t.Errorf("last PATCH must be the redeploy body:\n got  %#v\n want %#v", last.Body, wantBody)
			}
			// #203 rule: no instance PATCH may carry tlsContexts null; the
			// redeploy body has no endpoint at all.
			assertNoEndpoint(t, last.Body)
			if d.Id() != "1" {
				t.Errorf("id = %q, want 1", d.Id())
			}
		})
	}
}

func TestApimFlexGatewayCreate_RedeployFailureIsWarning(t *testing.T) {
	srv := newFlexCreateServer(t, false, true)
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, apimFlexGatewayBaseRaw("1.0.0"))

	diags := resourceApimFlexGatewayCreate(context.Background(), d, apimFlexGatewayTestMeta(srv.URL))

	if diags.HasError() {
		t.Fatalf("a failed redeploy must not be an error (it would taint the resource): %s", diagsText(diags))
	}
	var found *diag.Diagnostic
	for i := range diags {
		if diags[i].Summary == "Unable to redeploy Flex Gateway instance 1" {
			found = &diags[i]
		}
	}
	if found == nil {
		t.Fatalf("expected the redeploy warning, got: %s", diagsText(diags))
	}
	if found.Severity != diag.Warning {
		t.Errorf("severity = %v, want Warning", found.Severity)
	}
	if !strings.Contains(found.Detail, "deployment rejected") {
		t.Errorf("detail should carry the API body, got %q", found.Detail)
	}
	if d.Id() != "1" {
		t.Errorf("resource must stay in state with id 1, got %q", d.Id())
	}
	// Create still reaches Read: the last request is the instance GET, so the
	// last *mutating* call is the failed redeploy.
	if last := srv.last(); last.Method != http.MethodPatch || last.Body["deployment"] == nil {
		t.Errorf("last mutating call should be the redeploy PATCH, got %v", last)
	}
}

func TestApimFlexGatewayCreate_EarlierErrorSkipsRedeploy(t *testing.T) {
	// the instance POST succeeds, the upstream POST fails: no redeploy.
	var mu sync.Mutex
	var seq []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet {
			seq = append(seq, r.Method+" "+r.URL.Path)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == flexCreateInstPath:
			_, _ = w.Write([]byte(`{"id":1}`))
		case r.Method == http.MethodPost && r.URL.Path == flexCreateUpPath:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"bad upstream"}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, apimFlexGatewayBaseRaw("1.0.0"))

	diags := resourceApimFlexGatewayCreate(context.Background(), d, apimFlexGatewayTestMeta(ts.URL))

	if !diags.HasError() {
		t.Fatalf("expected the upstream error, got: %s", diagsText(diags))
	}
	for _, s := range seq {
		if s == "PATCH "+flexCreateInstXapiPath {
			t.Errorf("no PATCH expected after an earlier error, got sequence %v", seq)
		}
	}
}
