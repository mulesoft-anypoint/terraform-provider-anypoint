package anypoint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	private_space "github.com/mulesoft-anypoint/anypoint-client-go/private_space"
)

const (
	tgwTestShare   = "share-1"
	tgwTestAccount = "111122223333"
	tgwTestRoute   = "10.0.0.0/20"
	tgwTestID      = "tgw-0abc"
	tgwTestName    = "cfg-name"
	tgwShareErrMsg = `{"message":"Transit gateway attachment with the same resource share id already exists"}`
)

type tgwReq struct {
	Method, Path, Body string
}

type tgwMockResp struct {
	status int
	body   any // marshalled as JSON; a string is written verbatim
}

// tgwMock answers each "METHOD path" with its scripted responses in order;
// the last response repeats. Every request is recorded.
type tgwMock struct {
	mu     sync.Mutex
	reqs   []tgwReq
	routes map[string][]tgwMockResp
	hits   map[string]int
}

func (m *tgwMock) on(method, path string, resps ...tgwMockResp) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[method+" "+path] = resps
}

func (m *tgwMock) requests() []tgwReq {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]tgwReq(nil), m.reqs...)
}

func (m *tgwMock) count(method, path string) int {
	n := 0
	for _, r := range m.requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func (m *tgwMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	body := string(b)
	var buf bytes.Buffer
	if len(b) > 0 && json.Compact(&buf, b) == nil {
		body = buf.String()
	}
	key := r.Method + " " + r.URL.Path
	m.mu.Lock()
	m.reqs = append(m.reqs, tgwReq{r.Method, r.URL.Path, body})
	rs := m.routes[key]
	n := m.hits[key]
	m.hits[key]++
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if len(rs) == 0 {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"no mock for ` + key + `"}`))
		return
	}
	if n >= len(rs) {
		n = len(rs) - 1
	}
	resp := rs[n]
	w.WriteHeader(resp.status)
	switch v := resp.body.(type) {
	case nil:
	case string:
		_, _ = w.Write([]byte(v))
	default:
		_ = json.NewEncoder(w).Encode(v)
	}
}

type tgwFlowEnv struct {
	t    *testing.T
	mock *tgwMock
	meta ProviderConfOutput
	org  string
}

var tgwTestOrgSeq int64

// newTGWFlowEnv starts a mock private_space API and shortens the retry
// seams. Each env gets a fresh org id so lock claims never leak across tests.
func newTGWFlowEnv(t *testing.T) *tgwFlowEnv {
	t.Helper()
	oldDelay, oldBudget, oldBase, oldMax := tgwRescueRecheckDelay, tgwAttachRetryBudget, tgwAttachRetryBase, tgwAttachRetryMaxDelay
	tgwRescueRecheckDelay, tgwAttachRetryBudget, tgwAttachRetryBase, tgwAttachRetryMaxDelay = 5*time.Millisecond, 500*time.Millisecond, 2*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() {
		tgwRescueRecheckDelay, tgwAttachRetryBudget, tgwAttachRetryBase, tgwAttachRetryMaxDelay = oldDelay, oldBudget, oldBase, oldMax
	})
	mock := &tgwMock{routes: map[string][]tgwMockResp{}, hits: map[string]int{}}
	ts := httptest.NewServer(mock)
	t.Cleanup(ts.Close)
	cfg := private_space.NewConfiguration()
	cfg.Servers = private_space.ServerConfigurations{{URL: ts.URL}}
	return &tgwFlowEnv{
		t:    t,
		mock: mock,
		meta: ProviderConfOutput{
			access_token:       "x",
			server_index:       0,
			privatespaceclient: private_space.NewAPIClient(cfg),
		},
		org: fmt.Sprintf("org-%d", atomic.AddInt64(&tgwTestOrgSeq, 1)),
	}
}

func (e *tgwFlowEnv) spacePath(ps string) string {
	return "/organizations/" + e.org + "/privatespaces/" + ps + "/transitgateways"
}

func (e *tgwFlowEnv) attachPath(ps, tgw string) string { return e.spacePath(ps) + "/" + tgw }
func (e *tgwFlowEnv) orgPath() string                  { return "/organizations/" + e.org + "/transitgateways" }
func (e *tgwFlowEnv) orgTGWPath(tgw string) string     { return e.orgPath() + "/" + tgw }

// raw builds a raw config of the resource: strs become strings, attributes
// named in unknown become unknown, routes becomes a set, the rest is null.
func (e *tgwFlowEnv) raw(ps string, strs map[string]string, routes []string, unknown ...string) cty.Value {
	all := map[string]string{"org_id": e.org, "private_space_id": ps}
	for k, v := range strs {
		all[k] = v
	}
	return tgwFlowRaw(all, routes, unknown...)
}

func tgwFlowRaw(strs map[string]string, routes []string, unknown ...string) cty.Value {
	typ := resourcePrivateSpaceTransitGateway().CoreConfigSchema().ImpliedType()
	unk := map[string]bool{}
	for _, u := range unknown {
		unk[u] = true
	}
	attrs := map[string]cty.Value{}
	for name, at := range typ.AttributeTypes() {
		switch {
		case unk[name]:
			attrs[name] = cty.UnknownVal(at)
		case name == "routes" && routes != nil:
			var vals []cty.Value
			for _, r := range routes {
				vals = append(vals, cty.StringVal(r))
			}
			attrs[name] = cty.SetVal(vals)
		default:
			if s, ok := strs[name]; ok {
				attrs[name] = cty.StringVal(s)
			} else {
				attrs[name] = cty.NullVal(at)
			}
		}
	}
	return cty.ObjectVal(attrs)
}

func (e *tgwFlowEnv) createModeRaw(ps string) cty.Value {
	return e.raw(ps, map[string]string{
		"name":                   tgwTestName,
		"resource_share_id":      tgwTestShare,
		"resource_share_account": tgwTestAccount,
	}, []string{tgwTestRoute})
}

func (e *tgwFlowEnv) attachModeRaw(ps, tgw string) cty.Value {
	return e.raw(ps, map[string]string{"transit_gateway_id": tgw}, []string{tgwTestRoute})
}

func tgwShim(raw cty.Value) *terraform.ResourceConfig {
	return terraform.NewResourceConfigShimmed(raw, resourcePrivateSpaceTransitGateway().CoreConfigSchema())
}

// apply runs plan + apply of the resource the way ApplyResourceChange does.
func (e *tgwFlowEnv) apply(ctx context.Context, state *terraform.InstanceState, raw cty.Value) (*terraform.InstanceState, diag.Diagnostics) {
	e.t.Helper()
	r := resourcePrivateSpaceTransitGateway()
	d, err := r.Diff(ctx, state, tgwShim(raw), e.meta)
	if err != nil {
		e.t.Fatalf("diff: %v", err)
	}
	if d == nil {
		e.t.Fatal("expected a diff")
	}
	d.RawConfig = raw
	return r.Apply(ctx, state, d, e.meta)
}

func tgwPerSpace(id, name, space, status string) map[string]any {
	return map[string]any{
		"id":        id,
		"name":      name,
		"accountId": "999900001111",
		"spec": map[string]any{
			"resourceShare": map[string]any{"id": tgwTestShare, "account": tgwTestAccount},
			"region":        "us-east-1",
			"spaceName":     space,
		},
		"status": map[string]any{
			"gateway":     "refreshing",
			"attachment":  status,
			"tgwResource": "https://console.aws.amazon.com/tgw",
			"routes":      []string{tgwTestRoute},
		},
	}
}

func tgwOrgAtt(space, status string) map[string]any {
	return map[string]any{
		"spec":   map[string]any{"spaceName": space},
		"status": map[string]any{"attachment": status, "routes": []string{}},
	}
}

func tgwOrgList(id, name, account string, atts ...map[string]any) []any {
	if atts == nil {
		atts = []map[string]any{}
	}
	return []any{map[string]any{
		"id":   id,
		"name": name,
		"spec": map[string]any{
			"resourceShare":   map[string]any{"id": tgwTestShare, "account": account},
			"region":          "us-east-1",
			"ch2AwsAccountId": "999900001111",
		},
		"tgwResource": "https://console.aws.amazon.com/tgw",
		"attachments": atts,
	}}
}

// tgwDecode turns a mock JSON value into the client model.
func tgwDecode(t *testing.T, v any) private_space.TransitGateway {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var tgw private_space.TransitGateway
	if err := json.Unmarshal(b, &tgw); err != nil {
		t.Fatal(err)
	}
	return tgw
}

func tgwCreateBody() string {
	return `{"name":"` + tgwTestName + `","resourceShareAccount":"` + tgwTestAccount + `","resourceShareId":"` + tgwTestShare + `","routes":["` + tgwTestRoute + `"]}`
}

func assertTGWRequests(t *testing.T, got []tgwReq, want []tgwReq) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		var g, w strings.Builder
		for _, r := range got {
			fmt.Fprintf(&g, "  %s %s %s\n", r.Method, r.Path, r.Body)
		}
		for _, r := range want {
			fmt.Fprintf(&w, "  %s %s %s\n", r.Method, r.Path, r.Body)
		}
		t.Fatalf("request sequence mismatch\n got:\n%s want:\n%s", g.String(), w.String())
	}
}

func tgwErrors(diags diag.Diagnostics) []diag.Diagnostic {
	var out []diag.Diagnostic
	for _, d := range diags {
		if d.Severity == diag.Error {
			out = append(out, d)
		}
	}
	return out
}

func tgwOriginalCreateDetail() string { return "HTTP 400: " + tgwShareErrMsg }

// ---- Create, attach mode ----

func TestTGWCreate_AttachMode_BareArrayBody(t *testing.T) {
	e := newTGWFlowEnv(t)
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID), tgwMockResp{200, []any{tgwPerSpace(tgwTestID, "org-name", "space-b", "refreshing")}})

	state, diags := e.apply(context.Background(), nil, e.attachModeRaw("ps-b", tgwTestID))
	if diags.HasError() {
		t.Fatalf("apply: %v", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.attachPath("ps-b", tgwTestID), `["` + tgwTestRoute + `"]`},
	})
	if want := e.org + "/ps-b/" + tgwTestID; state == nil || state.ID != want {
		t.Fatalf("id = %v, want %s", state, want)
	}
	for k, want := range map[string]string{
		"transit_gateway_id":     tgwTestID,
		"name":                   "org-name",
		"space_name":             "space-b",
		"status_attachment":      "refreshing",
		"resource_share_id":      tgwTestShare,
		"resource_share_account": tgwTestAccount,
	} {
		if got := state.Attributes[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestTGWCreate_AttachMode_RetryOn409(t *testing.T) {
	e := newTGWFlowEnv(t)
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID),
		tgwMockResp{409, `{"message":"transit gateway is not ready"}`},
		tgwMockResp{200, []any{tgwPerSpace(tgwTestID, "org-name", "space-b", "refreshing")}},
	)
	state, diags := e.apply(context.Background(), nil, e.attachModeRaw("ps-b", tgwTestID))
	if diags.HasError() {
		t.Fatalf("apply: %v", diags)
	}
	if n := e.mock.count("POST", e.attachPath("ps-b", tgwTestID)); n != 2 {
		t.Fatalf("attach POSTs = %d, want 2", n)
	}
	if state == nil || state.ID == "" {
		t.Fatal("id not set")
	}
}

func TestTGWCreate_AttachMode_RetryHonoursCtx(t *testing.T) {
	e := newTGWFlowEnv(t)
	// The budget outlives ctx, so only ctx can end the wait.
	tgwAttachRetryBudget, tgwAttachRetryBase, tgwAttachRetryMaxDelay = time.Hour, time.Second, time.Second
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID), tgwMockResp{409, tgwAssociatedMsg})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, diags := e.apply(ctx, nil, e.attachModeRaw("ps-b", tgwTestID))
	if el := time.Since(start); el < 90*time.Millisecond || el > 500*time.Millisecond {
		t.Fatalf("returned after %v, want a return on the 100ms ctx deadline", el)
	}
	if n := e.mock.count("POST", e.attachPath("ps-b", tgwTestID)); n != 1 {
		t.Errorf("attach POSTs = %d, want 1 (cancelled during the first wait)", n)
	}
	errs := tgwErrors(diags)
	if len(errs) != 1 || errs[0].Summary != "Unable to attach transit gateway "+tgwTestID+" to private space ps-b" {
		t.Fatalf("diags = %v", diags)
	}
}

const (
	tgwAssociatedMsg  = `{"message":"Transit gateway attachment is already associated with this space, try another space or detach and reattach"}`
	tgwDetachHint     = "The platform keeps a detached attachment on this private space for several minutes after a detach; retry the apply in a few minutes."
	tgwUnknownTGWHint = "Transit gateway " + tgwTestID + " is not known to this Anypoint organization yet. If another anypoint_private_space_transit_gateway creates it, " +
		"reference that resource's transit_gateway_id instead of the literal id so Terraform creates it first."
)

func TestTGWRetryDefaults(t *testing.T) {
	if tgwAttachRetryBudget != 15*time.Minute {
		t.Errorf("tgwAttachRetryBudget = %v, want 15m (re-attach lockout after a detach lasts ~11 min)", tgwAttachRetryBudget)
	}
	if tgwAttachRetryMaxDelay > time.Minute {
		t.Errorf("tgwAttachRetryMaxDelay = %v, want <= 1m so the budget is used", tgwAttachRetryMaxDelay)
	}
}

func TestTGWCreate_AttachMode_RetryOn409x3(t *testing.T) {
	e := newTGWFlowEnv(t)
	busy := tgwMockResp{409, tgwAssociatedMsg}
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID), busy, busy, busy,
		tgwMockResp{200, []any{tgwPerSpace(tgwTestID, "org-name", "space-b", "refreshing")}})
	state, diags := e.apply(context.Background(), nil, e.attachModeRaw("ps-b", tgwTestID))
	if diags.HasError() {
		t.Fatalf("apply: %v", diags)
	}
	if n := e.mock.count("POST", e.attachPath("ps-b", tgwTestID)); n != 4 {
		t.Fatalf("attach POSTs = %d, want 4", n)
	}
	if state == nil || state.ID != e.org+"/ps-b/"+tgwTestID {
		t.Fatalf("id not set: %v", state)
	}
}

func TestTGWCreate_AttachMode_BudgetExhausted_DetachHint(t *testing.T) {
	e := newTGWFlowEnv(t)
	tgwAttachRetryBudget = 30 * time.Millisecond
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID), tgwMockResp{409, tgwAssociatedMsg})
	_, diags := e.apply(context.Background(), nil, e.attachModeRaw("ps-b", tgwTestID))
	errs := tgwErrors(diags)
	if len(errs) != 1 {
		t.Fatalf("want one error, got %v", diags)
	}
	if !strings.Contains(errs[0].Detail, tgwDetachHint) || !strings.Contains(errs[0].Detail, "already associated with this space") {
		t.Errorf("detail must carry the API body and the detach hint:\n%s", errs[0].Detail)
	}
	if n := e.mock.count("POST", e.attachPath("ps-b", tgwTestID)); n < 2 {
		t.Errorf("attach POSTs = %d, want retries within the budget", n)
	}
}

func TestTGWCreate_AttachMode_UnknownTGW_Hint(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{400, `{"status":"FAILURE","message":"Transit gateway attachment not found"}`},
		{404, `{"message":"Transit gateway Not Found"}`},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			e := newTGWFlowEnv(t)
			e.mock.on("POST", e.attachPath("ps-b", tgwTestID), tgwMockResp{tc.status, tc.body})
			_, diags := e.apply(context.Background(), nil, e.attachModeRaw("ps-b", tgwTestID))
			errs := tgwErrors(diags)
			if len(errs) != 1 {
				t.Fatalf("want one error, got %v", diags)
			}
			if !strings.Contains(errs[0].Detail, tgwUnknownTGWHint) || !strings.Contains(errs[0].Detail, tc.body) {
				t.Errorf("detail must carry the API body and the unknown-tgw hint:\n%s", errs[0].Detail)
			}
			if n := e.mock.count("POST", e.attachPath("ps-b", tgwTestID)); n != 1 {
				t.Errorf("attach POSTs = %d, want 1 (not retried)", n)
			}
		})
	}
}

func TestTGWCreate_AttachMode_OtherError_NoHint(t *testing.T) {
	e := newTGWFlowEnv(t)
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID), tgwMockResp{400, `{"message":"routes overlap"}`})
	_, diags := e.apply(context.Background(), nil, e.attachModeRaw("ps-b", tgwTestID))
	errs := tgwErrors(diags)
	if len(errs) != 1 || errs[0].Detail != `HTTP 400: {"message":"routes overlap"}` {
		t.Fatalf("want the raw API error only, got %v", diags)
	}
}

func TestTGWCreate_Rescue_AttachRetryOn409(t *testing.T) {
	zero := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount, tgwOrgAtt("space-b", "detached"))
	e := rescueEnv(t, tgwTestName, zero, zero)
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID),
		tgwMockResp{409, tgwAssociatedMsg},
		tgwMockResp{200, []any{tgwPerSpace(tgwTestID, tgwTestName, "space-b", "refreshing")}})
	state, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	if len(diags) != 0 {
		t.Fatalf("diags: %v", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
		{"GET", e.orgPath(), ""},
		{"POST", e.attachPath("ps-b", tgwTestID), `["` + tgwTestRoute + `"]`},
		{"POST", e.attachPath("ps-b", tgwTestID), `["` + tgwTestRoute + `"]`},
	})
	if state == nil || state.ID != e.org+"/ps-b/"+tgwTestID {
		t.Fatalf("id not set: %v", state)
	}
}

func TestTGWCreate_Rescue_AttachBudgetExhausted_BothErrorsAndHint(t *testing.T) {
	zero := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount)
	e := rescueEnv(t, tgwTestName, zero, zero)
	tgwAttachRetryBudget = 30 * time.Millisecond
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID), tgwMockResp{409, tgwAssociatedMsg})
	_, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(errs) != 2 || errs[0].Detail != tgwOriginalCreateDetail() || !strings.Contains(errs[1].Detail, tgwDetachHint) {
		t.Fatalf("want the original error and the attach error with the detach hint, got %v", diags)
	}
	if n := e.mock.count("POST", e.attachPath("ps-b", tgwTestID)); n < 2 {
		t.Errorf("rescue attach POSTs = %d, want retries", n)
	}
}

func TestTGWCreate_ModeRuleAtApply(t *testing.T) {
	e := newTGWFlowEnv(t)
	// At plan time transit_gateway_id was unknown, so the SDK skipped
	// ConflictsWith; at apply the raw config is known.
	r := resourcePrivateSpaceTransitGateway()
	planned := e.raw("ps-b", map[string]string{"name": "n"}, []string{tgwTestRoute}, "transit_gateway_id")
	if diags := r.Validate(tgwShim(planned)); diags.HasError() {
		t.Fatalf("plan-time Validate must pass with an unknown id: %v", diags)
	}
	ctx := context.Background()
	d, err := r.Diff(ctx, nil, tgwShim(planned), e.meta)
	if err != nil || d == nil {
		t.Fatalf("diff: %v, %v", d, err)
	}
	d.RawConfig = e.raw("ps-b", map[string]string{"transit_gateway_id": tgwTestID, "name": "n"}, []string{tgwTestRoute})
	_, diags := r.Apply(ctx, nil, d, e.meta)
	errs := tgwErrors(diags)
	if len(errs) != 1 {
		t.Fatalf("want one error, got %v", diags)
	}
	if errs[0].Summary != "Unable to create transit gateway for private space ps-b" ||
		!strings.Contains(errs[0].Detail, "transit_gateway_id cannot be combined with name, resource_share_id or resource_share_account") {
		t.Errorf("unexpected diag: %+v", errs[0])
	}
	if n := len(e.mock.requests()); n != 0 {
		t.Fatalf("want zero requests, got %d", n)
	}
}

// The SDK skips unknown values in ConflictsWith / ExactlyOneOf, so an invalid
// mix passes plan while the referenced id is unknown. This is why Create
// re-checks the mode rule (TestTGWCreate_ModeRuleAtApply).
func TestTGWValidate_UnknownTransitGatewayID(t *testing.T) {
	r := resourcePrivateSpaceTransitGateway()
	base := map[string]string{"org_id": "org", "private_space_id": "ps"}
	if diags := r.Validate(tgwShim(tgwFlowRaw(base, []string{tgwTestRoute}, "transit_gateway_id"))); diags.HasError() {
		t.Errorf("valid attach config with unknown id: %v", diags)
	}
	withName := map[string]string{"org_id": "org", "private_space_id": "ps", "name": "n"}
	if diags := r.Validate(tgwShim(tgwFlowRaw(withName, []string{tgwTestRoute}, "transit_gateway_id"))); diags.HasError() {
		t.Errorf("SDK now rejects unknown id + name at plan; the apply-time check may be redundant: %v", diags)
	}
}

// ---- Create, create mode ----

func TestTGWCreate_CreateMode_201(t *testing.T) {
	e := newTGWFlowEnv(t)
	e.mock.on("POST", e.spacePath("ps-a"), tgwMockResp{201, tgwPerSpace(tgwTestID, tgwTestName, "space-a", "pending")})
	state, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-a"))
	if diags.HasError() {
		t.Fatalf("apply: %v", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{{"POST", e.spacePath("ps-a"), tgwCreateBody()}})
	if want := e.org + "/ps-a/" + tgwTestID; state.ID != want {
		t.Errorf("id = %q, want %q", state.ID, want)
	}
	if got := state.Attributes["transit_gateway_id"]; got != tgwTestID {
		t.Errorf("transit_gateway_id = %q", got)
	}
	if got := state.Attributes["status_attachment"]; got != "pending" {
		t.Errorf("status_attachment = %q, want state from the POST response", got)
	}
	if !tgwOrgLockFor(e.org).Claimed(tgwTestShare) {
		t.Error("share not claimed after create")
	}
}

// rescueEnv scripts the create-mode 400 on ps-b and an attach that succeeds.
func rescueEnv(t *testing.T, orgName string, orgLists ...[]any) *tgwFlowEnv {
	e := newTGWFlowEnv(t)
	e.mock.on("POST", e.spacePath("ps-b"), tgwMockResp{400, tgwShareErrMsg})
	var resps []tgwMockResp
	for _, l := range orgLists {
		resps = append(resps, tgwMockResp{200, l})
	}
	e.mock.on("GET", e.orgPath(), resps...)
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID), tgwMockResp{200, []any{tgwPerSpace(tgwTestID, orgName, "space-b", "refreshing")}})
	return e
}

func TestTGWCreate_Rescue_ZeroLive(t *testing.T) {
	zero := tgwOrgList(tgwTestID, "old-name", tgwTestAccount, tgwOrgAtt("space-b", "detached"))
	e := rescueEnv(t, "old-name", zero, zero)
	e.mock.on("PATCH", e.orgTGWPath(tgwTestID), tgwMockResp{200, []any{tgwPerSpace(tgwTestID, tgwTestName, "space-b", "refreshing")}})

	state, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	if len(diags) != 0 {
		t.Fatalf("diags: %v", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
		{"GET", e.orgPath(), ""},
		{"POST", e.attachPath("ps-b", tgwTestID), `["` + tgwTestRoute + `"]`},
		{"PATCH", e.orgTGWPath(tgwTestID), `{"name":"` + tgwTestName + `"}`},
	})
	if want := e.org + "/ps-b/" + tgwTestID; state.ID != want {
		t.Errorf("id = %q, want %q", state.ID, want)
	}
	if got := state.Attributes["name"]; got != tgwTestName {
		t.Errorf("name = %q, want %q", got, tgwTestName)
	}
	if !tgwOrgLockFor(e.org).Claimed(tgwTestShare) {
		t.Error("share not claimed after rescue")
	}
}

func TestTGWCreate_Rescue_SameName_NoPatch(t *testing.T) {
	zero := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount)
	e := rescueEnv(t, tgwTestName, zero, zero)
	state, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	if len(diags) != 0 {
		t.Fatalf("diags: %v", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
		{"GET", e.orgPath(), ""},
		{"POST", e.attachPath("ps-b", tgwTestID), `["` + tgwTestRoute + `"]`},
	})
	if state.ID == "" {
		t.Error("id not set")
	}
}

func TestTGWCreate_Rescue_LiveElsewhere_Hint(t *testing.T) {
	live := tgwOrgList(tgwTestID, "org-name", tgwTestAccount, tgwOrgAtt("space-a", "refreshing"), tgwOrgAtt("space-x", "detached"))
	e := rescueEnv(t, "org-name", live)
	e.mock.on("GET", e.spacePath("ps-b"), tgwMockResp{200, []any{}})

	state, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(errs) != 1 {
		t.Fatalf("want one error, got %v", diags)
	}
	hint := tgwShareConflictHint(tgwDecode(t, live[0]), "ps-b")
	if !strings.Contains(errs[0].Detail, hint) || !strings.Contains(errs[0].Detail, tgwOriginalCreateDetail()) {
		t.Errorf("detail must carry the hint and the original error, got:\n%s", errs[0].Detail)
	}
	if errs[0].Summary != "Unable to create transit gateway for private space ps-b" {
		t.Errorf("summary = %q", errs[0].Summary)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
		{"GET", e.spacePath("ps-b"), ""},
	})
	if state != nil && state.ID != "" {
		t.Errorf("id must stay empty, got %q", state.ID)
	}
}

func TestTGWCreate_Rescue_ClaimedInProcess_Hint(t *testing.T) {
	empty := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount)
	e := rescueEnv(t, tgwTestName, empty)
	e.mock.on("POST", e.spacePath("ps-a"), tgwMockResp{201, tgwPerSpace(tgwTestID, tgwTestName, "space-a", "pending")})

	if _, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-a")); diags.HasError() {
		t.Fatalf("first create: %v", diags)
	}
	_, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(errs) != 1 {
		t.Fatalf("want one error, got %v", diags)
	}
	for _, want := range []string{
		"is already used by another anypoint_private_space_transit_gateway in this apply",
		`set transit_gateway_id = "` + tgwTestID + `"`,
	} {
		if !strings.Contains(errs[0].Detail, want) {
			t.Errorf("detail missing %q:\n%s", want, errs[0].Detail)
		}
	}
	if strings.Contains(errs[0].Detail, "is attached to .") {
		t.Errorf("claim hint must not use the empty live-space wording:\n%s", errs[0].Detail)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-a"), tgwCreateBody()},
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
	})
}

// The org list is eventually consistent: right after A's 201 it may not list
// the share at all. The claim alone must produce the hint, naming A's tgw id.
func TestTGWCreate_Rescue_ClaimedInProcess_NotListed_Hint(t *testing.T) {
	e := rescueEnv(t, tgwTestName, []any{})
	e.mock.on("POST", e.spacePath("ps-a"), tgwMockResp{201, tgwPerSpace(tgwTestID, tgwTestName, "space-a", "pending")})

	if _, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-a")); diags.HasError() {
		t.Fatalf("first create: %v", diags)
	}
	_, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(errs) != 1 {
		t.Fatalf("want one error, got %v", diags)
	}
	for _, want := range []string{
		"Transit gateway " + tgwTestID + " already uses this resource share",
		"is already used by another anypoint_private_space_transit_gateway in this apply",
		`set transit_gateway_id = "` + tgwTestID + `"`,
		tgwOriginalCreateDetail(),
	} {
		if !strings.Contains(errs[0].Detail, want) {
			t.Errorf("detail missing %q:\n%s", want, errs[0].Detail)
		}
	}
	if strings.Contains(errs[0].Detail, `("")`) {
		t.Errorf("hint must omit an unknown name:\n%s", errs[0].Detail)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-a"), tgwCreateBody()},
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
	})
}

func TestTGWCreate_Rescue_ListsDisagree_NoAttach(t *testing.T) {
	zero := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount)
	live := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount, tgwOrgAtt("space-a", "refreshing"))
	e := rescueEnv(t, tgwTestName, zero, live)
	_, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(errs) != 1 || !strings.Contains(errs[0].Detail, tgwShareConflictHint(tgwDecode(t, live[0]), "ps-b")) {
		t.Fatalf("want the share hint from the second read, got %v", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
		{"GET", e.orgPath(), ""},
	})
}

func TestTGWCreate_Rescue_AlreadyOnThisSpace_ImportHint(t *testing.T) {
	live := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount, tgwOrgAtt("space-b", "available"))
	e := rescueEnv(t, tgwTestName, live)
	e.mock.on("GET", e.spacePath("ps-b"), tgwMockResp{200, []any{tgwPerSpace(tgwTestID, tgwTestName, "space-b", "available")}})
	_, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(errs) != 1 {
		t.Fatalf("want one error, got %v", diags)
	}
	for _, want := range []string{"already attached to private space ps-b", "terraform import", e.org + "/ps-b/" + tgwTestID} {
		if !strings.Contains(errs[0].Detail, want) {
			t.Errorf("detail missing %q:\n%s", want, errs[0].Detail)
		}
	}
	if e.mock.count("POST", e.attachPath("ps-b", tgwTestID)) != 0 {
		t.Error("must not attach")
	}
}

func TestTGWCreate_Rescue_LookupError_OriginalError(t *testing.T) {
	e := newTGWFlowEnv(t)
	e.mock.on("POST", e.spacePath("ps-b"), tgwMockResp{400, tgwShareErrMsg})
	e.mock.on("GET", e.orgPath(), tgwMockResp{500, `{"message":"boom"}`})
	_, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	want := diag.Diagnostics{{
		Severity: diag.Error,
		Summary:  "Unable to create transit gateway for private space ps-b",
		Detail:   tgwOriginalCreateDetail(),
	}}
	if !reflect.DeepEqual(diags, want) {
		t.Fatalf("diags = %#v, want the original error only", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
	})
}

func TestTGWCreate_Rescue_NoShareMatch_OriginalError(t *testing.T) {
	e := newTGWFlowEnv(t)
	e.mock.on("POST", e.spacePath("ps-b"), tgwMockResp{400, `{"message":"routes overlap"}`})
	other := tgwOrgList("tgw-0other", "other", tgwTestAccount)
	other[0].(map[string]any)["spec"].(map[string]any)["resourceShare"] = map[string]any{"id": "share-other", "account": tgwTestAccount}
	e.mock.on("GET", e.orgPath(), tgwMockResp{200, other})
	_, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(diags) != 1 || len(errs) != 1 || errs[0].Detail != `HTTP 400: {"message":"routes overlap"}` {
		t.Fatalf("diags = %v, want the original error only", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
	})
}

func TestTGWCreate_Rescue_AccountMismatch(t *testing.T) {
	e := rescueEnv(t, tgwTestName, tgwOrgList(tgwTestID, tgwTestName, "999988887777"))
	_, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(errs) != 1 {
		t.Fatalf("want one error, got %v", diags)
	}
	for _, want := range []string{tgwOriginalCreateDetail(), `"999988887777"`, `"` + tgwTestAccount + `"`, "resource_share_account"} {
		if !strings.Contains(errs[0].Detail, want) {
			t.Errorf("detail missing %q:\n%s", want, errs[0].Detail)
		}
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"POST", e.spacePath("ps-b"), tgwCreateBody()},
		{"GET", e.orgPath(), ""},
	})
}

func TestTGWCreate_Rescue_AttachFails_BothErrors(t *testing.T) {
	zero := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount)
	e := rescueEnv(t, tgwTestName, zero, zero)
	e.mock.on("POST", e.attachPath("ps-b", tgwTestID), tgwMockResp{400, `{"message":"attach boom"}`})
	state, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
	errs := tgwErrors(diags)
	if len(errs) != 2 {
		t.Fatalf("want two errors, got %v", diags)
	}
	if errs[0].Summary != "Unable to create transit gateway for private space ps-b" || errs[0].Detail != tgwOriginalCreateDetail() {
		t.Errorf("first diag = %+v, want the original create error", errs[0])
	}
	if errs[1].Summary != "Unable to attach transit gateway "+tgwTestID+" to private space ps-b" || !strings.Contains(errs[1].Detail, "attach boom") {
		t.Errorf("second diag = %+v, want the attach error", errs[1])
	}
	if state != nil && state.ID != "" {
		t.Errorf("id must stay empty, got %q", state.ID)
	}
	if tgwOrgLockFor(e.org).Claimed(tgwTestShare) {
		t.Error("failed rescue must not claim the share")
	}
}

func TestTGWCreate_Rescue_NamePatch500_Warning_IDKept(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		patches int
	}{
		{"409 retried three times", 409, 3},
		{"500 not retried", 500, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zero := tgwOrgList(tgwTestID, "old-name", tgwTestAccount)
			e := rescueEnv(t, "old-name", zero, zero)
			e.mock.on("PATCH", e.orgTGWPath(tgwTestID), tgwMockResp{tc.status, `{"message":"busy"}`})
			state, diags := e.apply(context.Background(), nil, e.createModeRaw("ps-b"))
			if diags.HasError() {
				t.Fatalf("want warnings only, got %v", diags)
			}
			if len(diags) != 1 || diags[0].Severity != diag.Warning || diags[0].Summary != "Unable to update name for transit gateway "+tgwTestID {
				t.Fatalf("diags = %v", diags)
			}
			if n := e.mock.count("PATCH", e.orgTGWPath(tgwTestID)); n != tc.patches {
				t.Errorf("PATCH attempts = %d, want %d", n, tc.patches)
			}
			if want := e.org + "/ps-b/" + tgwTestID; state == nil || state.ID != want {
				t.Fatalf("id not kept: %v", state)
			}
			if got := state.Attributes["name"]; got != "old-name" {
				t.Errorf("name = %q, want the real org name so the next plan retries", got)
			}
		})
	}
}

func TestTGWCreate_ConcurrentSameShare_OneAttach(t *testing.T) {
	e := newTGWFlowEnv(t)
	zero := tgwOrgList(tgwTestID, tgwTestName, tgwTestAccount)
	e.mock.on("GET", e.orgPath(), tgwMockResp{200, zero})
	for _, ps := range []string{"ps-a", "ps-b"} {
		e.mock.on("POST", e.spacePath(ps), tgwMockResp{400, tgwShareErrMsg})
		e.mock.on("POST", e.attachPath(ps, tgwTestID), tgwMockResp{200, []any{tgwPerSpace(tgwTestID, tgwTestName, ps, "refreshing")}})
	}
	var wg sync.WaitGroup
	results := make([]diag.Diagnostics, 2)
	for i, ps := range []string{"ps-a", "ps-b"} {
		wg.Add(1)
		go func(i int, ps string) {
			defer wg.Done()
			r := resourcePrivateSpaceTransitGateway()
			raw := e.createModeRaw(ps)
			d, err := r.Diff(context.Background(), nil, tgwShim(raw), e.meta)
			if err != nil {
				results[i] = diag.Diagnostics{{Severity: diag.Error, Summary: err.Error()}}
				return
			}
			d.RawConfig = raw
			_, results[i] = r.Apply(context.Background(), nil, d, e.meta)
		}(i, ps)
	}
	wg.Wait()
	attaches := e.mock.count("POST", e.attachPath("ps-a", tgwTestID)) + e.mock.count("POST", e.attachPath("ps-b", tgwTestID))
	if attaches != 1 {
		t.Fatalf("attach POSTs = %d, want exactly 1", attaches)
	}
	failed := 0
	for _, r := range results {
		if r.HasError() {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("want one success and one hint, got %v", results)
	}
}

func TestTGWCreate_LockCtxCancelled(t *testing.T) {
	e := newTGWFlowEnv(t)
	held, err := acquireTGWOrgLock(context.Background(), e.org)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, diags := e.apply(ctx, nil, e.createModeRaw("ps-a"))
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("returned after %v, want < 200ms", el)
	}
	errs := tgwErrors(diags)
	if len(errs) != 1 || errs[0].Summary != "Unable to create transit gateway for private space ps-a" {
		t.Fatalf("diags = %v", diags)
	}
	if n := len(e.mock.requests()); n != 0 {
		t.Fatalf("want zero requests, got %d", n)
	}
}

// ---- Update / Delete ----

func tgwRoutesKey(route string) string {
	return "routes." + strconv.Itoa(schema.HashSchema(&schema.Schema{Type: schema.TypeString})(route))
}

// tgwV1114State is a create-mode state as written by v1.11.4 (no timeouts).
func tgwV1114State(org, ps string) *terraform.InstanceState {
	id := org + "/" + ps + "/" + tgwTestID
	return &terraform.InstanceState{
		ID: id,
		Attributes: map[string]string{
			"id":                       id,
			"org_id":                   org,
			"private_space_id":         ps,
			"transit_gateway_id":       tgwTestID,
			"name":                     tgwTestName,
			"resource_share_id":        tgwTestShare,
			"resource_share_account":   tgwTestAccount,
			"routes.#":                 "1",
			tgwRoutesKey(tgwTestRoute): tgwTestRoute,
			"account_id":               "999900001111",
			"region":                   "us-east-1",
			"space_name":               "space-a",
			"status_gateway":           "available",
			"status_attachment":        "pending",
			"tgw_resource_url":         "https://console.aws.amazon.com/tgw",
			"last_updated":             "Monday, 16-Nov-26 10:00:00 UTC",
		},
	}
}

// tgwImportedState is what Read writes after `terraform import`.
func tgwImportedState(org, ps string) *terraform.InstanceState {
	s := tgwV1114State(org, ps)
	delete(s.Attributes, "last_updated")
	s.Attributes["space_name"] = "space-b"
	return s
}

func TestTGWUpdate_AttachMode_NoNamePatch(t *testing.T) {
	e := newTGWFlowEnv(t)
	state := tgwImportedState(e.org, "ps-b")
	e.mock.on("PATCH", e.attachPath("ps-b", tgwTestID), tgwMockResp{200, []any{map[string]any{"routes": []string{"10.9.0.0/20"}}}})
	updated := tgwPerSpace(tgwTestID, tgwTestName, "space-b", "refreshing")
	updated["status"].(map[string]any)["routes"] = []string{"10.9.0.0/20"}
	e.mock.on("GET", e.spacePath("ps-b"), tgwMockResp{200, []any{updated}})

	// Attach-mode raw config that still carries a name (possible when the
	// id was unknown at plan time): the routes change applies, the
	// org-level name is never patched.
	raw := e.raw("ps-b", map[string]string{"transit_gateway_id": tgwTestID, "name": "other-name"}, []string{"10.9.0.0/20"})
	_, diags := e.apply(context.Background(), state, raw)
	if diags.HasError() {
		t.Fatalf("apply: %v", diags)
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"PATCH", e.attachPath("ps-b", tgwTestID), `{"routes":["10.9.0.0/20"]}`},
		{"GET", e.spacePath("ps-b"), ""},
	})
}

func TestTGWDelete_ReleasesClaim(t *testing.T) {
	e := newTGWFlowEnv(t)
	r := resourcePrivateSpaceTransitGateway()
	a := tgwV1114State(e.org, "ps-a")
	b := tgwImportedState(e.org, "ps-b") // attach mode: reads the same share back
	e.mock.on("DELETE", e.attachPath("ps-a", tgwTestID), tgwMockResp{204, nil})
	e.mock.on("DELETE", e.attachPath("ps-b", tgwTestID), tgwMockResp{204, nil})
	l := tgwOrgLockFor(e.org)
	l.Claim(tgwTestShare, a.ID)

	if _, diags := r.Apply(context.Background(), b, &terraform.InstanceDiff{Destroy: true}, e.meta); diags.HasError() {
		t.Fatalf("delete b: %v", diags)
	}
	if !l.Claimed(tgwTestShare) {
		t.Fatal("deleting the attach-mode resource dropped the creating resource's claim")
	}
	if _, diags := r.Apply(context.Background(), a, &terraform.InstanceDiff{Destroy: true}, e.meta); diags.HasError() {
		t.Fatalf("delete a: %v", diags)
	}
	if l.Claimed(tgwTestShare) {
		t.Fatal("claim not released by the owning resource's Delete")
	}
	assertTGWRequests(t, e.mock.requests(), []tgwReq{
		{"DELETE", e.attachPath("ps-b", tgwTestID), ""},
		{"DELETE", e.attachPath("ps-a", tgwTestID), ""},
	})
}

// ---- Diff ----

func tgwDiff(t *testing.T, state *terraform.InstanceState, raw cty.Value) *terraform.InstanceDiff {
	t.Helper()
	d, err := resourcePrivateSpaceTransitGateway().Diff(context.Background(), state, tgwShim(raw), nil)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	return d
}

func assertTGWEmptyDiff(t *testing.T, d *terraform.InstanceDiff) {
	t.Helper()
	if d != nil && !d.Empty() {
		var keys []string
		for k, a := range d.Attributes {
			keys = append(keys, fmt.Sprintf("%s: %q -> %q (requiresNew=%v)", k, a.Old, a.New, a.RequiresNew))
		}
		t.Fatalf("want empty diff, got:\n  %s", strings.Join(keys, "\n  "))
	}
}

func TestTGWDiff_UpgradeCreateModeUnchanged(t *testing.T) {
	cfg := tgwFlowRaw(map[string]string{
		"org_id": "org", "private_space_id": "ps-a",
		"name": tgwTestName, "resource_share_id": tgwTestShare, "resource_share_account": tgwTestAccount,
	}, []string{tgwTestRoute})
	assertTGWEmptyDiff(t, tgwDiff(t, tgwV1114State("org", "ps-a"), cfg))
}

func TestTGWDiff_ImportedAttachConfig(t *testing.T) {
	cfg := tgwFlowRaw(map[string]string{"org_id": "org", "private_space_id": "ps-b", "transit_gateway_id": tgwTestID}, []string{tgwTestRoute})
	assertTGWEmptyDiff(t, tgwDiff(t, tgwImportedState("org", "ps-b"), cfg))
}

func TestTGWDiff_CreateToAttachMigration(t *testing.T) {
	cfg := tgwFlowRaw(map[string]string{"org_id": "org", "private_space_id": "ps-a", "transit_gateway_id": tgwTestID}, []string{tgwTestRoute})
	assertTGWEmptyDiff(t, tgwDiff(t, tgwV1114State("org", "ps-a"), cfg))
}

func TestTGWDiff_UnknownTransitGatewayIDRequiresNew(t *testing.T) {
	cfg := tgwFlowRaw(map[string]string{"org_id": "org", "private_space_id": "ps-b"}, []string{tgwTestRoute}, "transit_gateway_id")
	d := tgwDiff(t, tgwImportedState("org", "ps-b"), cfg)
	if d == nil {
		t.Fatal("want a diff")
	}
	a, ok := d.Attributes["transit_gateway_id"]
	if !ok || !a.RequiresNew || !a.NewComputed {
		t.Fatalf("transit_gateway_id diff = %+v, want computed + RequiresNew", a)
	}
}
