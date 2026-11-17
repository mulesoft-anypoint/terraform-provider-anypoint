package anypoint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/mulesoft-anypoint/anypoint-client-go/private_space"
)

const (
	psTestOrg  = "org"
	psTestID   = "ps-1"
	psSuccess  = "InfrastructureProvisionSuccess"
	psProgress = "InfrastructureProvisionInProgress"
)

// psStep is one scripted answer of the GET private space endpoint.
type psStep struct {
	code    int
	status  string
	message string
}

// psSeqServer answers every GET with the next scripted step (the last one
// repeats) and counts the requests.
type psSeqServer struct {
	mu    sync.Mutex
	steps []psStep
	gets  int
}

func (s *psSeqServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.Lock()
	i := s.gets
	if i >= len(s.steps) {
		i = len(s.steps) - 1
	}
	s.gets++
	step := s.steps[i]
	s.mu.Unlock()
	if step.code != 0 && step.code != http.StatusOK {
		w.WriteHeader(step.code)
		_, _ = w.Write([]byte(`{"message":"scripted"}`))
		return
	}
	body := map[string]any{"id": psTestID}
	if step.status != "" {
		body["provisioning"] = map[string]any{"status": step.status, "message": step.message}
	}
	_ = json.NewEncoder(w).Encode(body)
}

func psTestMeta(url string) ProviderConfOutput {
	cfg := private_space.NewConfiguration()
	cfg.Servers = private_space.ServerConfigurations{{URL: url}}
	return ProviderConfOutput{
		access_token:       "x",
		server_index:       0,
		privatespaceclient: private_space.NewAPIClient(cfg),
	}
}

// psFastPolling shrinks the poll seams to milliseconds for the test.
func psFastPolling(t *testing.T) {
	t.Helper()
	oldInterval, oldMax := privateSpacePollInterval, privateSpaceMaxConsecutivePollErrors
	privateSpacePollInterval = 2 * time.Millisecond
	privateSpaceMaxConsecutivePollErrors = 5
	t.Cleanup(func() {
		privateSpacePollInterval, privateSpaceMaxConsecutivePollErrors = oldInterval, oldMax
	})
}

func diagsText(diags diag.Diagnostics) string {
	var b strings.Builder
	for _, d := range diags {
		b.WriteString(d.Summary + " | " + d.Detail + "\n")
	}
	return b.String()
}

func TestPrivateSpaceStatusTerminal(t *testing.T) {
	for status, want := range map[string]bool{
		"":                                false,
		psSuccess:                         false,
		psProgress:                        false,
		"InfrastructureProvisionFailed":   true,
		"SomethingError":                  true,
		"ProvisionError":                  true,
		"Something that is not terminal":  false,
		"InfrastructureProvisionPending":  false,
		"InfrastructureProvisionFailure":  true,
		"InfrastructureProvisionInFlight": false,
	} {
		if got := privateSpaceStatusTerminal(status); got != want {
			t.Errorf("privateSpaceStatusTerminal(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestWaitPrivateSpaceProvisioned(t *testing.T) {
	tests := []struct {
		name        string
		steps       []psStep
		wantErr     bool
		wantGets    int
		wantContain []string
	}{
		{name: "in progress then success", steps: []psStep{{status: psProgress}, {status: psProgress}, {status: psSuccess}}, wantGets: 3},
		{name: "503 then success", steps: []psStep{{code: 503}, {status: psSuccess}}, wantGets: 2},
		{name: "429 then success", steps: []psStep{{code: 429}, {status: psSuccess}}, wantGets: 2},
		{name: "transient errors are not consecutive", steps: []psStep{{code: 503}, {code: 503}, {status: psProgress}, {code: 503}, {code: 503}, {status: psSuccess}}, wantGets: 6},
		{name: "five consecutive 503", steps: []psStep{{code: 503}}, wantErr: true, wantGets: 5, wantContain: []string{"503"}},
		{name: "404", steps: []psStep{{code: 404}}, wantErr: true, wantGets: 1, wantContain: []string{"404"}},
		{name: "failed carries message", steps: []psStep{{status: psProgress}, {status: "InfrastructureProvisionFailed", message: "quota exceeded in us-east-2"}}, wantErr: true, wantGets: 2, wantContain: []string{"quota exceeded in us-east-2"}},
		{name: "error status", steps: []psStep{{status: "SomethingError", message: "boom"}}, wantErr: true, wantGets: 1, wantContain: []string{"boom"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			psFastPolling(t)
			srv := &psSeqServer{steps: tc.steps}
			ts := httptest.NewServer(srv)
			defer ts.Close()
			pco := psTestMeta(ts.URL)

			ps, diags := waitPrivateSpaceProvisioned(context.Background(), &pco, psTestOrg, psTestID)
			if diags.HasError() != tc.wantErr {
				t.Fatalf("error = %v, want %v: %s", diags.HasError(), tc.wantErr, diagsText(diags))
			}
			if !tc.wantErr {
				if ps == nil || func() string { st, _ := privateSpaceProvisioning(ps); return st }() != psSuccess {
					t.Fatalf("expected the last GET object with Success status, got %+v", ps)
				}
			}
			if srv.gets != tc.wantGets {
				t.Errorf("GET count = %d, want %d", srv.gets, tc.wantGets)
			}
			for _, s := range tc.wantContain {
				if !strings.Contains(diagsText(diags), s) {
					t.Errorf("diagnostics %q do not contain %q", diagsText(diags), s)
				}
			}
		})
	}
}

func TestWaitPrivateSpaceProvisioned_Deadline(t *testing.T) {
	psFastPolling(t)
	srv := &psSeqServer{steps: []psStep{{status: psProgress}}}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	pco := psTestMeta(ts.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, diags := waitPrivateSpaceProvisioned(ctx, &pco, psTestOrg, psTestID)
	if !diags.HasError() {
		t.Fatal("expected an error on deadline")
	}
	text := diagsText(diags)
	if !strings.Contains(text, "terraform untaint") {
		t.Errorf("deadline diagnostic must mention terraform untaint, got %q", text)
	}
	if !strings.Contains(text, psTestID) {
		t.Errorf("deadline diagnostic must name the space id, got %q", text)
	}
}

func TestWaitPrivateSpaceAfterUpdate(t *testing.T) {
	t.Run("success returns immediately", func(t *testing.T) {
		psFastPolling(t)
		srv := &psSeqServer{steps: []psStep{{status: psSuccess}}}
		ts := httptest.NewServer(srv)
		defer ts.Close()
		pco := psTestMeta(ts.URL)
		if diags := waitPrivateSpaceAfterUpdate(context.Background(), &pco, psTestOrg, psTestID); len(diags) != 0 {
			t.Fatalf("unexpected diagnostics: %s", diagsText(diags))
		}
		if srv.gets != 1 {
			t.Errorf("GET count = %d, want 1", srv.gets)
		}
	})
	t.Run("empty status returns immediately", func(t *testing.T) {
		psFastPolling(t)
		srv := &psSeqServer{steps: []psStep{{}}}
		ts := httptest.NewServer(srv)
		defer ts.Close()
		pco := psTestMeta(ts.URL)
		if diags := waitPrivateSpaceAfterUpdate(context.Background(), &pco, psTestOrg, psTestID); len(diags) != 0 {
			t.Fatalf("unexpected diagnostics: %s", diagsText(diags))
		}
		if srv.gets != 1 {
			t.Errorf("GET count = %d, want 1", srv.gets)
		}
	})
	t.Run("in progress then success waits", func(t *testing.T) {
		psFastPolling(t)
		srv := &psSeqServer{steps: []psStep{{status: psProgress}, {status: psProgress}, {status: psSuccess}}}
		ts := httptest.NewServer(srv)
		defer ts.Close()
		pco := psTestMeta(ts.URL)
		if diags := waitPrivateSpaceAfterUpdate(context.Background(), &pco, psTestOrg, psTestID); len(diags) != 0 {
			t.Fatalf("unexpected diagnostics: %s", diagsText(diags))
		}
		if srv.gets < 3 {
			t.Errorf("GET count = %d, want at least 3", srv.gets)
		}
	})
	t.Run("deadline is a warning", func(t *testing.T) {
		psFastPolling(t)
		srv := &psSeqServer{steps: []psStep{{status: psProgress}}}
		ts := httptest.NewServer(srv)
		defer ts.Close()
		pco := psTestMeta(ts.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		diags := waitPrivateSpaceAfterUpdate(ctx, &pco, psTestOrg, psTestID)
		if len(diags) == 0 {
			t.Fatal("expected a warning on deadline")
		}
		if diags.HasError() {
			t.Fatalf("a deadline after the PATCH must be a warning, got %s", diagsText(diags))
		}
		if diags[0].Severity != diag.Warning {
			t.Errorf("severity = %v, want warning", diags[0].Severity)
		}
	})
	t.Run("first GET error does not fail the update", func(t *testing.T) {
		psFastPolling(t)
		srv := &psSeqServer{steps: []psStep{{code: 503}}}
		ts := httptest.NewServer(srv)
		defer ts.Close()
		pco := psTestMeta(ts.URL)
		if diags := waitPrivateSpaceAfterUpdate(context.Background(), &pco, psTestOrg, psTestID); diags.HasError() {
			t.Fatalf("a failed status GET after a PATCH must not be an error: %s", diagsText(diags))
		}
	})
}

// psMock is a stateful private space API: POST creates, GET walks the
// provisioning script, PATCH records its body and re-opens provisioning.
type psMock struct {
	mu          sync.Mutex
	events      []string
	patchBodies []map[string]any
	post        map[string]any
	// remaining number of GETs that still answer InProgress
	progressLeft int
	egress       bool
	iam          bool
}

func (m *psMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	raw, _ := io.ReadAll(r.Body)
	switch r.Method {
	case http.MethodPost:
		m.events = append(m.events, "POST")
		_ = json.Unmarshal(raw, &m.post)
		m.progressLeft = 2
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": psTestID, "name": m.post["name"]})
	case http.MethodPatch:
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		m.patchBodies = append(m.patchBodies, body)
		if v, ok := body["enableEgress"].(bool); ok {
			m.egress = v
		}
		if v, ok := body["enableIAMRole"].(bool); ok {
			m.iam = v
		}
		m.progressLeft = 1
		m.events = append(m.events, "PATCH")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": psTestID})
	case http.MethodGet:
		status, isolation := psSuccess, true
		if m.progressLeft > 0 {
			m.progressLeft--
			status, isolation = psProgress, false
		}
		m.events = append(m.events, "GET:"+status)
		network, _ := m.post["network"].(map[string]any)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                     psTestID,
			"name":                   m.post["name"],
			"organizationId":         psTestOrg,
			"status":                 "Active",
			"region":                 "us-east-2",
			"provisioning":           map[string]any{"status": status, "message": "m"},
			"network":                map[string]any{"region": network["region"], "cidrBlock": network["cidrBlock"]},
			"environments":           map[string]any{"type": "all"},
			"enableEgress":           m.egress,
			"enableIAMRole":          m.iam,
			"enableNetworkIsolation": isolation,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func psCreateConfig(extra map[string]any) map[string]any {
	cfg := map[string]any{
		"org_id":             psTestOrg,
		"name":               "tf-ps",
		"network_region":     "us-east-2",
		"network_cidr_block": "172.23.0.0/22",
		"environments_type":  "all",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func psApplyCreate(t *testing.T, mock *psMock, cfg map[string]any) *terraform.InstanceState {
	t.Helper()
	psFastPolling(t)
	ts := httptest.NewServer(mock)
	defer ts.Close()
	meta := psTestMeta(ts.URL)
	r := resourcePrivateSpace()
	ctx := context.Background()
	diff, err := r.Diff(ctx, nil, terraform.NewResourceConfigRaw(cfg), meta)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	state, diags := r.Apply(ctx, nil, diff, meta)
	if diags.HasError() {
		t.Fatalf("apply: %s", diagsText(diags))
	}
	return state
}

func TestPrivateSpaceCreate_Order(t *testing.T) {
	t.Run("planned egress true patches after the first wait and re-waits", func(t *testing.T) {
		mock := &psMock{}
		state := psApplyCreate(t, mock, psCreateConfig(map[string]any{"enable_egress": true}))
		if state == nil || state.ID != psTestID {
			t.Fatalf("create did not set id %s: %+v", psTestID, state)
		}
		want := []string{
			"POST",
			"GET:" + psProgress, "GET:" + psProgress, "GET:" + psSuccess,
			"PATCH",
			"GET:" + psProgress, "GET:" + psSuccess,
			"GET:" + psSuccess, // final Read
		}
		if got := strings.Join(mock.events, ","); got != strings.Join(want, ",") {
			t.Fatalf("event order\n got  %v\n want %v", mock.events, want)
		}
		if len(mock.patchBodies) != 1 {
			t.Fatalf("expected one PATCH, got %d", len(mock.patchBodies))
		}
		body := mock.patchBodies[0]
		if body["enableEgress"] != true {
			t.Errorf("PATCH must carry enableEgress:true built from the plan, got %v", body)
		}
		if _, ok := body["enableNetworkIsolation"]; ok {
			t.Errorf("PATCH must never carry enableNetworkIsolation, got %v", body)
		}
		if got := state.Attributes["enable_egress"]; got != "true" {
			t.Errorf("state enable_egress = %q, want true", got)
		}
		if got := state.Attributes["enable_network_isolation"]; got != "true" {
			t.Errorf("state enable_network_isolation = %q, want the API value true", got)
		}
	})
	t.Run("defaults send no PATCH", func(t *testing.T) {
		mock := &psMock{}
		state := psApplyCreate(t, mock, psCreateConfig(nil))
		if state == nil || state.ID != psTestID {
			t.Fatalf("create did not set id: %+v", state)
		}
		if len(mock.patchBodies) != 0 {
			t.Errorf("no PATCH expected with defaults, got %v", mock.patchBodies)
		}
		want := []string{
			"POST",
			"GET:" + psProgress, "GET:" + psProgress, "GET:" + psSuccess,
			"GET:" + psSuccess, // final Read
		}
		if got := strings.Join(mock.events, ","); got != strings.Join(want, ",") {
			t.Fatalf("event order\n got  %v\n want %v", mock.events, want)
		}
		if got := state.Attributes["enable_network_isolation"]; got != "true" {
			t.Errorf("state enable_network_isolation = %q, want true", got)
		}
	})
	t.Run("timeout after create keeps the id", func(t *testing.T) {
		psFastPolling(t)
		mock := &psMock{}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				mock.mu.Lock()
				mock.progressLeft = 1000
				mock.mu.Unlock()
			}
			mock.ServeHTTP(w, r)
		}))
		defer ts.Close()
		meta := psTestMeta(ts.URL)
		r := resourcePrivateSpace()
		diff, err := r.Diff(context.Background(), nil, terraform.NewResourceConfigRaw(psCreateConfig(nil)), meta)
		if err != nil {
			t.Fatalf("diff: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		// The deadline cancels the wait, not Apply: Apply derives its own create timeout.
		state, diags := r.Apply(ctx, nil, diff, meta)
		if !diags.HasError() {
			t.Fatalf("expected an error")
		}
		if state == nil || state.ID != psTestID {
			t.Fatalf("a timeout must keep the id so the space is not orphaned, got %+v", state)
		}
		if !strings.Contains(diagsText(diags), "terraform untaint") {
			t.Errorf("missing untaint hint: %s", diagsText(diags))
		}
	})
}

func TestPrivateSpaceResource_Timeouts(t *testing.T) {
	r := resourcePrivateSpace()
	if r.Timeouts == nil || r.Timeouts.Create == nil || r.Timeouts.Update == nil {
		t.Fatalf("create and update timeouts must be declared: %+v", r.Timeouts)
	}
	if *r.Timeouts.Create != 60*time.Minute || *r.Timeouts.Update != 60*time.Minute {
		t.Errorf("timeouts = %v / %v, want 60m / 60m", *r.Timeouts.Create, *r.Timeouts.Update)
	}
}

func TestPrivateSpacePatchBody_NoIsolation(t *testing.T) {
	for _, isolation := range []bool{true, false} {
		d := schema.TestResourceDataRaw(t, resourcePrivateSpace().Schema, psCreateConfig(map[string]any{
			"enable_egress":            true,
			"enable_iam_role":          true,
			"enable_network_isolation": isolation,
		}))
		raw, err := json.Marshal(newPrivateSpacePatchBody(d))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := m["enableNetworkIsolation"]; ok {
			t.Errorf("isolation=%v: body must not carry enableNetworkIsolation: %s", isolation, raw)
		}
		if m["enableEgress"] != true || m["enableIAMRole"] != true {
			t.Errorf("isolation=%v: egress/iam builder must be unchanged: %s", isolation, raw)
		}
	}
	for _, attr := range updatablePrivateSpaceAttributes() {
		if attr == "enable_network_isolation" {
			t.Error("enable_network_isolation must not be an updatable attribute")
		}
	}
}

func TestPrivateSpaceSchema_IsolationDeprecated(t *testing.T) {
	r := resourcePrivateSpace()
	if err := r.InternalValidate(nil, true); err != nil {
		t.Fatalf("InternalValidate: %v", err)
	}
	s := r.Schema["enable_network_isolation"]
	if s.Deprecated == "" {
		t.Error("enable_network_isolation must be deprecated")
	}
	if !s.Optional || !s.Computed || s.Default != nil {
		t.Errorf("want Optional+Computed without Default, got optional=%v computed=%v default=%v", s.Optional, s.Computed, s.Default)
	}
	meta := ProviderConfOutput{}
	ctx := context.Background()
	state := psV1114State(true)
	for name, cfg := range map[string]map[string]any{
		"false in config": psCreateConfig(map[string]any{"enable_network_isolation": false}),
		"omitted":         psCreateConfig(nil),
	} {
		diff, err := r.Diff(ctx, state, terraform.NewResourceConfigRaw(cfg), meta)
		if err != nil {
			t.Fatalf("%s: diff: %v", name, err)
		}
		if diff != nil && !diff.Empty() {
			t.Errorf("%s: expected no diff, got %v", name, diff.Attributes)
		}
	}
}

// psV1114State is the state a v1.11.4 apply leaves behind for a minimal config.
func psV1114State(isolation bool) *terraform.InstanceState {
	attrs := map[string]string{
		"id":                            psTestID,
		"org_id":                        psTestOrg,
		"name":                          "tf-ps",
		"network_region":                "us-east-2",
		"network_cidr_block":            "172.23.0.0/22",
		"environments_type":             "all",
		"network_inbound_static_ips.#":  "0",
		"network_outbound_static_ips.#": "0",
		"enable_egress":                 "false",
		"enable_iam_role":               "false",
		"enable_network_isolation":      fmt.Sprintf("%v", isolation),
	}
	return &terraform.InstanceState{ID: psTestID, Attributes: attrs}
}

func TestPrivateSpaceDiff_UpgradeNoChange(t *testing.T) {
	r := resourcePrivateSpace()
	diff, err := r.Diff(context.Background(), psV1114State(true), terraform.NewResourceConfigRaw(psCreateConfig(nil)), ProviderConfOutput{})
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff != nil && !diff.Empty() {
		t.Fatalf("v1.11.4 state with unchanged config must plan nothing, got %v", diff.Attributes)
	}
}

func TestPrivateSpacePlannedDiffers(t *testing.T) {
	apiWith := func(egress, iam bool) *private_space.PrivateSpace {
		ps := private_space.NewPrivateSpace()
		ps.SetEnableEgress(egress)
		ps.SetEnableIAMRole(iam)
		env := private_space.NewPrivateSpaceAssociatedEnvironments()
		env.SetType("all")
		ps.SetEnvironments(*env)
		return ps
	}
	rules := func(cidr string) []any {
		return []any{map[string]any{"cidr_block": cidr, "protocol": "tcp", "from_port": 8081, "to_port": 8081, "type": "inbound"}}
	}
	apiRules := func(cidr string) *private_space.PrivateSpace {
		ps := apiWith(false, false)
		fr := private_space.NewFirewallRule()
		fr.SetCidrBlock(cidr)
		fr.SetProtocol("tcp")
		fr.SetFromPort(8081)
		fr.SetToPort(8081)
		fr.SetType("inbound")
		ps.SetFirewallRules([]private_space.FirewallRule{*fr})
		return ps
	}
	tests := []struct {
		name string
		cfg  map[string]any
		ps   *private_space.PrivateSpace
		want bool
	}{
		{"defaults match", psCreateConfig(nil), apiWith(false, false), false},
		{"egress planned, api false", psCreateConfig(map[string]any{"enable_egress": true}), apiWith(false, false), true},
		{"egress planned, api true", psCreateConfig(map[string]any{"enable_egress": true}), apiWith(true, false), false},
		{"iam planned, api false", psCreateConfig(map[string]any{"enable_iam_role": true}), apiWith(false, false), true},
		{"egress false planned, api true is not sent", psCreateConfig(nil), apiWith(true, false), false},
		{"isolation in config never differs", psCreateConfig(map[string]any{"enable_network_isolation": false}), apiWith(false, false), false},
		{"environments type differs", psCreateConfig(map[string]any{"environments_type": "sandbox"}), apiWith(false, false), true},
		{"firewall rules equal", psCreateConfig(map[string]any{"firewall_rules": rules("10.0.0.0/16")}), apiRules("10.0.0.0/16"), false},
		{"firewall rules differ", psCreateConfig(map[string]any{"firewall_rules": rules("10.1.0.0/16")}), apiRules("10.0.0.0/16"), true},
		{"firewall rules planned, api none", psCreateConfig(map[string]any{"firewall_rules": rules("10.0.0.0/16")}), apiWith(false, false), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, resourcePrivateSpace().Schema, tc.cfg)
			if got := privateSpacePlannedDiffers(d, tc.ps); got != tc.want {
				t.Errorf("privateSpacePlannedDiffers = %v, want %v", got, tc.want)
			}
		})
	}
}
