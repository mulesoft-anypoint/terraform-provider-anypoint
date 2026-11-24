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
	flexCreateInstGetPath  = "/api/v1/organizations/org/environments/env/apis/1"
)

type flexCreateCall struct {
	Method string
	Path   string
	Body   map[string]any
}

func (c flexCreateCall) String() string { return c.Method + " " + c.Path }

// flexCreateOpts shapes the fake Anypoint API used by the Create tests.
//   - withDefault: the instance POST also creates a default upstream (label
//     null). Without it the list is empty until the first upstream POST, as
//     observed live in the #206 spike (endpoint_uri is computed-only, so the
//     provider never sends it).
//   - deployment: the deployment block the instance GET returns, i.e. what the
//     platform resolved from the instance POST. Nil means no deployment block.
//   - failRedeploy: a PATCH carrying `deployment` answers 500.
//   - failUpstreamPost: the upstream POST answers 400.
//   - instanceGone: every instance GET answers 404.
type flexCreateOpts struct {
	withDefault      bool
	deployment       map[string]any
	failRedeploy     bool
	failUpstreamPost bool
	instanceGone     bool
}

// flexCreateServer records every request (all) and the mutating ones
// (calls: POST/PATCH/DELETE, query strings ignored) and keeps the upstream
// list stateful.
type flexCreateServer struct {
	*httptest.Server
	opts      flexCreateOpts
	mu        sync.Mutex
	all       []flexCreateCall
	calls     []flexCreateCall
	upstreams []map[string]any
	nextID    int
}

func newFlexCreateServer(t *testing.T, opts flexCreateOpts) *flexCreateServer {
	t.Helper()
	s := &flexCreateServer{opts: opts, nextID: 1}
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
		}
		call := flexCreateCall{Method: r.Method, Path: path, Body: body}
		s.all = append(s.all, call)
		if r.Method != http.MethodGet {
			s.calls = append(s.calls, call)
		}
		switch {
		case r.Method == http.MethodPost && path == flexCreateInstPath:
			if opts.withDefault {
				s.upstreams = append(s.upstreams, map[string]any{"id": "d", "label": nil, "uri": "https://placeholder.example"})
			}
			_, _ = w.Write([]byte(`{"id":1}`))
		case r.Method == http.MethodPost && path == flexCreateUpPath:
			if opts.failUpstreamPost {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"bad upstream"}`))
				return
			}
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
			if _, isRedeploy := body["deployment"]; isRedeploy && opts.failRedeploy {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"deployment rejected"}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet:
			if opts.instanceGone {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"not found"}`))
				return
			}
			out := map[string]any{"id": 1}
			if opts.deployment != nil {
				out["deployment"] = opts.deployment
			}
			_ = json.NewEncoder(w).Encode(out)
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

// requests returns every recorded request, GETs included.
func (s *flexCreateServer) requests() []flexCreateCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]flexCreateCall{}, s.all...)
}

// platformDeployment is the deployment block the instance GET returns after
// the instance POST: what the platform resolved. gatewayVersion is filled in
// by the platform when the config leaves it unset.
func platformDeployment(expectedStatus string) map[string]any {
	return map[string]any{
		"environmentId":  "env",
		"type":           "HY",
		"expectedStatus": expectedStatus,
		"targetId":       "target",
		"targetName":     "target-name",
		"gatewayVersion": "1.14.4",
	}
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
	undeployed := apimFlexGatewayRawWith("1.0.0", map[string]any{"deployment_expected_status": "undeployed"})
	// config leaves deployment_gateway_version unset; the platform resolves it.
	wantPlatform := func(status string) map[string]any {
		return map[string]any{
			"environmentId": "env", "type": "HY", "expectedStatus": status, "overwrite": false,
			"targetId": "target", "targetName": "target-name", "gatewayVersion": "1.14.4",
		}
	}
	tests := []struct {
		name           string
		raw            map[string]any
		opts           flexCreateOpts
		want           []string
		wantDeployment map[string]any
	}{
		{
			// routed path: the routing Read refreshes deployment_* before the
			// redeploy, so the body carries the platform-resolved values.
			name: "routed",
			raw:  apimFlexGatewayBaseRaw("1.0.0"),
			opts: flexCreateOpts{deployment: platformDeployment("deployed")},
			want: []string{
				"POST " + flexCreateInstPath,
				"POST " + flexCreateUpPath,
				"PATCH " + flexCreateInstXapiPath, // routing
				"PATCH " + flexCreateInstXapiPath, // redeploy
			},
			wantDeployment: wantPlatform("deployed"),
		},
		{
			name: "routed, expected status undeployed is preserved",
			raw:  undeployed,
			opts: flexCreateOpts{deployment: platformDeployment("undeployed")},
			want: []string{
				"POST " + flexCreateInstPath,
				"POST " + flexCreateUpPath,
				"PATCH " + flexCreateInstXapiPath, // routing
				"PATCH " + flexCreateInstXapiPath, // redeploy
			},
			wantDeployment: wantPlatform("undeployed"),
		},
		{
			// no routing Read happens: the body is built from the config.
			name: "no routing",
			raw:  noRouting(),
			opts: flexCreateOpts{deployment: platformDeployment("deployed")},
			want: []string{
				"POST " + flexCreateInstPath,
				"POST " + flexCreateUpPath,
				"PATCH " + flexCreateInstXapiPath, // redeploy
			},
			wantDeployment: map[string]any{
				"environmentId": "env", "type": "HY", "expectedStatus": "deployed", "overwrite": false,
				"targetId": "target", "targetName": "target-name", "gatewayVersion": "",
			},
		},
		{
			name: "default upstream present, deleted before redeploy",
			raw:  apimFlexGatewayBaseRaw("1.0.0"),
			opts: flexCreateOpts{withDefault: true, deployment: platformDeployment("deployed")},
			want: []string{
				"POST " + flexCreateInstPath,
				"POST " + flexCreateUpPath,
				"PATCH " + flexCreateInstXapiPath, // routing
				"DELETE " + flexCreateUpPath + "/d",
				"PATCH " + flexCreateInstXapiPath, // redeploy
			},
			wantDeployment: wantPlatform("deployed"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFlexCreateServer(t, tc.opts)
			d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, tc.raw)

			diags := resourceApimFlexGatewayCreate(context.Background(), d, apimFlexGatewayTestMeta(srv.URL))
			if diags.HasError() {
				t.Fatalf("unexpected error diags: %s", diagsText(diags))
			}
			if got := srv.sequence(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mutating call sequence mismatch:\n got  %v\n want %v", got, tc.want)
			}
			last := srv.last()
			wantBody := map[string]any{"deployment": tc.wantDeployment}
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
	srv := newFlexCreateServer(t, flexCreateOpts{failRedeploy: true})
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
	// Create still reaches Read: an instance GET follows the failed redeploy PATCH.
	reqs := srv.requests()
	redeploy := -1
	for i, c := range reqs {
		if c.Method == http.MethodPatch && c.Body["deployment"] != nil {
			redeploy = i
		}
	}
	if redeploy < 0 {
		t.Fatalf("no redeploy PATCH recorded: %v", reqs)
	}
	readAfter := false
	for _, c := range reqs[redeploy+1:] {
		if c.Method == http.MethodGet && c.Path == flexCreateInstGetPath {
			readAfter = true
		}
	}
	if !readAfter {
		t.Errorf("expected an instance GET after the failed redeploy PATCH, requests after it: %v", reqs[redeploy+1:])
	}
}

func TestApimFlexGatewayCreate_EarlierErrorSkipsRedeploy(t *testing.T) {
	// the instance POST succeeds, the upstream POST fails. Create still sends
	// the routing PATCH (existing behaviour) but must not redeploy.
	srv := newFlexCreateServer(t, flexCreateOpts{failUpstreamPost: true})
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, apimFlexGatewayBaseRaw("1.0.0"))

	diags := resourceApimFlexGatewayCreate(context.Background(), d, apimFlexGatewayTestMeta(srv.URL))

	if !diags.HasError() {
		t.Fatalf("expected the upstream error, got: %s", diagsText(diags))
	}
	var upstreamErr bool
	for _, dg := range diags {
		if dg.Severity == diag.Error && strings.HasPrefix(dg.Summary, "Unable to create Flex Gateway upstream") {
			upstreamErr = true
		}
	}
	if !upstreamErr {
		t.Errorf("expected the upstream error diag, got: %s", diagsText(diags))
	}
	seq := srv.sequence()
	if len(seq) < 2 || seq[0] != "POST "+flexCreateInstPath || seq[1] != "POST "+flexCreateUpPath {
		t.Fatalf("the instance and upstream POSTs must be reached, got %v", seq)
	}
	for _, c := range srv.requests() {
		if c.Method == http.MethodPatch {
			if _, redeploy := c.Body["deployment"]; redeploy {
				t.Errorf("no redeploy PATCH expected after an earlier error, got %#v", c.Body)
			}
		}
	}
}

func TestApimFlexGatewayCreate_InstanceGoneSkipsRedeploy(t *testing.T) {
	// the Read inside the routing update gets a 404 and clears the id: the
	// redeploy must not PATCH .../apis/ with an empty id.
	srv := newFlexCreateServer(t, flexCreateOpts{instanceGone: true})
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, apimFlexGatewayBaseRaw("1.0.0"))

	diags := resourceApimFlexGatewayCreate(context.Background(), d, apimFlexGatewayTestMeta(srv.URL))

	if diags.HasError() {
		t.Fatalf("unexpected error diags: %s", diagsText(diags))
	}
	if d.Id() != "" {
		t.Fatalf("test premise: id should be cleared by the 404 Read, got %q", d.Id())
	}
	for _, c := range srv.requests() {
		if c.Method == http.MethodPatch && c.Path != flexCreateInstXapiPath {
			t.Errorf("unexpected PATCH on %s", c.Path)
		}
		if c.Method == http.MethodPatch && c.Body["deployment"] != nil {
			t.Errorf("no redeploy expected once the instance is gone, got %#v", c.Body)
		}
	}
}
