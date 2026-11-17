package anypoint

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	application_manager_v2 "github.com/mulesoft-anypoint/anypoint-client-go/application_manager_v2"
)

// rtfVCoresRawConfig is rtfTestRawConfig with application.0.vcores set (when vcores > 0).
func rtfVCoresRawConfig(vcores float64, deploymentSettings map[string]any) map[string]any {
	raw := rtfTestRawConfig(deploymentSettings)
	if vcores > 0 {
		raw["application"].([]any)[0].(map[string]any)["vcores"] = vcores
	}
	return raw
}

func rtfTestBodyJSON(t *testing.T, raw map[string]any, sendResources, sendVCores bool) map[string]any {
	t.Helper()
	d := schema.TestResourceDataRaw(t, resourceRTFDeployment().Schema, raw)
	b, err := json.Marshal(newRTFDeploymentBody(d, sendResources, sendVCores))
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	return out
}

func TestRTFVCoresInRawConfig(t *testing.T) {
	appType := cty.Object(map[string]cty.Type{"vcores": cty.Number})
	root := func(app cty.Value) cty.Value {
		return cty.ObjectVal(map[string]cty.Value{"application": app})
	}
	app := func(v cty.Value) cty.Value {
		return cty.ListVal([]cty.Value{cty.ObjectVal(map[string]cty.Value{"vcores": v})})
	}
	tests := []struct {
		name string
		raw  cty.Value
		want bool
	}{
		{"null object", cty.NullVal(cty.Object(map[string]cty.Type{})), false},
		{"no application attribute", cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("x")}), false},
		{"application block absent (empty list)", root(cty.ListValEmpty(appType)), false},
		{"application null", root(cty.NullVal(cty.List(appType))), false},
		{"vcores null", root(app(cty.NullVal(cty.Number))), false},
		{"vcores unknown", root(app(cty.UnknownVal(cty.Number))), false},
		{"vcores 0.1", root(app(cty.NumberFloatVal(0.1))), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rtfVCoresInRawConfig(tc.raw); got != tc.want {
				t.Errorf("rtfVCoresInRawConfig() = %v, want %v", got, tc.want)
			}
		})
	}

	// Pin the helper to the real schema shape (CoreConfigSchema implied type).
	implied := resourceRTFDeployment().CoreConfigSchema().ImpliedType()
	for _, tc := range []struct {
		name   string
		vcores float64
		want   bool
	}{
		{"real schema, vcores 0.1", 0.1, true},
		{"real schema, vcores unset", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := rtfTestRawValue(t, implied, rtfVCoresRawConfig(tc.vcores, map[string]any{}))
			if got := rtfVCoresInRawConfig(raw); got != tc.want {
				t.Errorf("rtfVCoresInRawConfig() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewRTFDeploymentBody_VCores(t *testing.T) {
	// State carries an instance_type (as after a usage-based deployment) while the
	// user switched to vcores: sendVCores must win and omit instanceType.
	raw := rtfVCoresRawConfig(0.1, map[string]any{"instance_type": "mule.nano"})
	body := rtfTestBodyJSON(t, raw, false, true)
	app := body["application"].(map[string]any)
	if got := app["vCores"]; got != 0.1 {
		t.Errorf("application.vCores = %v, want 0.1", got)
	}
	ds := body["target"].(map[string]any)["deploymentSettings"].(map[string]any)
	if _, ok := ds["resources"]; ok {
		t.Errorf("resources must be absent, got %v", ds["resources"])
	}
	if _, ok := ds["instanceType"]; ok {
		t.Errorf("instanceType must be absent when vCores is sent, got %v", ds["instanceType"])
	}
}

func TestNewRTFDeploymentBody_NoVCoresWhenNotSent(t *testing.T) {
	// Echoed vCores in state (0.1) must not reach the wire when the config has none.
	raw := rtfVCoresRawConfig(0.1, map[string]any{"instance_type": "mule.nano"})
	body := rtfTestBodyJSON(t, raw, false, false)
	if _, ok := body["application"].(map[string]any)["vCores"]; ok {
		t.Errorf("application.vCores must be absent when sendVCores=false")
	}
	ds := body["target"].(map[string]any)["deploymentSettings"].(map[string]any)
	if ds["instanceType"] != "mule.nano" {
		t.Errorf("instanceType = %v, want mule.nano (unchanged behaviour)", ds["instanceType"])
	}
}

func rtfValidate(t *testing.T, raw map[string]any) diag.Diagnostics {
	t.Helper()
	r := resourceRTFDeployment()
	val := rtfTestRawValue(t, r.CoreConfigSchema().ImpliedType(), raw)
	return r.Validate(terraform.NewResourceConfigShimmed(val, r.CoreConfigSchema()))
}

func rtfErrors(diags diag.Diagnostics) []string {
	var out []string
	for _, d := range diags {
		if d.Severity == diag.Error {
			out = append(out, d.Summary+": "+d.Detail)
		}
	}
	return out
}

func TestRTFSchema_VCoresValidation(t *testing.T) {
	for _, tc := range []struct {
		vcores  float64
		wantErr bool
	}{{0.3, true}, {0.05, true}, {0.1, false}, {0.2, false}, {0.5, false}, {1, false}} {
		errs := rtfErrors(rtfValidate(t, rtfVCoresRawConfig(tc.vcores, map[string]any{})))
		if (len(errs) > 0) != tc.wantErr {
			t.Errorf("vcores %v: errors = %v, wantErr %v", tc.vcores, errs, tc.wantErr)
		}
	}
}

func TestRTFSchema_VCoresConflicts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vcores  float64
		ds      map[string]any
		wantErr bool
	}{
		{"vcores + resources", 0.1, map[string]any{"resources": rtfTestResources()}, true},
		{"vcores + instance_type", 0.1, map[string]any{"instance_type": "mule.nano"}, true},
		{"resources only", 0, map[string]any{"resources": rtfTestResources()}, false},
		{"instance_type only", 0, map[string]any{"instance_type": "mule.nano"}, false},
		{"vcores only", 0.1, map[string]any{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := rtfErrors(rtfValidate(t, rtfVCoresRawConfig(tc.vcores, tc.ds)))
			if (len(errs) > 0) != tc.wantErr {
				t.Errorf("errors = %v, wantErr %v", errs, tc.wantErr)
			}
		})
	}
}

// ---- httptest lifecycle -------------------------------------------------------

type rtfApplyHarness struct {
	t    *testing.T
	mock *rtfMockAppManager
	r    *schema.Resource
	meta ProviderConfOutput
}

func newRTFApplyHarness(t *testing.T, r *schema.Resource) *rtfApplyHarness {
	t.Helper()
	mock := &rtfMockAppManager{}
	ts := httptest.NewServer(mock)
	t.Cleanup(ts.Close)
	cfg := application_manager_v2.NewConfiguration()
	cfg.Servers = application_manager_v2.ServerConfigurations{{URL: ts.URL}}
	return &rtfApplyHarness{t: t, mock: mock, r: r, meta: ProviderConfOutput{
		access_token:     "x",
		appmanagerclient: application_manager_v2.NewAPIClient(cfg),
	}}
}

// diff plans rawCfg against state and returns the planned attribute paths.
func (h *rtfApplyHarness) diff(state *terraform.InstanceState, rawCfg map[string]any) (*terraform.InstanceDiff, []string) {
	h.t.Helper()
	diff, err := h.r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(rawCfg), h.meta)
	if err != nil {
		h.t.Fatalf("diff: %v", err)
	}
	if diff == nil {
		return nil, nil
	}
	var paths []string
	for k := range diff.Attributes {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	return diff, paths
}

func (h *rtfApplyHarness) apply(state *terraform.InstanceState, rawCfg map[string]any) *terraform.InstanceState {
	h.t.Helper()
	diff, _ := h.diff(state, rawCfg)
	if diff == nil {
		h.t.Fatal("expected a diff to apply")
	}
	diff.RawConfig = rtfTestRawValue(h.t, h.r.CoreConfigSchema().ImpliedType(), rawCfg)
	newState, diags := h.r.Apply(context.Background(), state, diff, h.meta)
	if diags.HasError() {
		h.t.Fatalf("apply: %v", diags)
	}
	return newState
}

func hasPath(paths []string, sub string) bool {
	for _, p := range paths {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func bodyApp(body map[string]any) map[string]any { return body["application"].(map[string]any) }

func TestRTFDeployment_VCoresLifecycle(t *testing.T) {
	h := newRTFApplyHarness(t, resourceRTFDeployment())

	// create with vcores 0.1: POST carries vCores, no resources
	cfg := rtfVCoresRawConfig(0.1, map[string]any{})
	state := h.apply(nil, cfg)
	if len(h.mock.bodies) != 1 {
		t.Fatalf("expected one POST, got %d", len(h.mock.bodies))
	}
	if got := bodyApp(h.mock.bodies[0])["vCores"]; got != 0.1 {
		t.Errorf("POST application.vCores = %v, want 0.1", got)
	}
	if _, ok := h.mock.bodies[0]["target"].(map[string]any)["deploymentSettings"].(map[string]any)["resources"]; ok {
		t.Errorf("POST must not carry resources")
	}
	if got := state.Attributes["application.0.vcores"]; got != "0.1" {
		t.Fatalf("state vcores = %q, want 0.1", got)
	}

	// same config again: no vcores entry in the diff
	if _, paths := h.diff(state, cfg); hasPath(paths, "application.0.vcores") {
		t.Errorf("unexpected vcores diff: %v", paths)
	}

	// resize in place
	state = h.apply(state, rtfVCoresRawConfig(0.2, map[string]any{}))
	if got := bodyApp(h.mock.bodies[1])["vCores"]; got != 0.2 {
		t.Errorf("PATCH application.vCores = %v, want 0.2", got)
	}
	if got := state.Attributes["application.0.vcores"]; got != "0.2" {
		t.Errorf("state vcores after resize = %q, want 0.2", got)
	}

	// vcores removed from config + another change: PATCH omits vCores, state keeps 0.2
	noV := rtfVCoresRawConfig(0, map[string]any{"jvm_args": "-Xmx64m"})
	if _, paths := h.diff(state, rtfVCoresRawConfig(0, map[string]any{})); hasPath(paths, "application.0.vcores") {
		t.Errorf("removing vcores from config must not plan a change: %v", paths)
	}
	state = h.apply(state, noV)
	if _, ok := bodyApp(h.mock.bodies[2])["vCores"]; ok {
		t.Errorf("PATCH without vcores in config must omit vCores, got %v", bodyApp(h.mock.bodies[2])["vCores"])
	}
	if got := state.Attributes["application.0.vcores"]; got != "0.2" {
		t.Errorf("state vcores after PATCH without vCores = %q, want 0.2 (kept)", got)
	}
}

// The API echoes vCores although the config sizes with resources (Runtime Fabric):
// no vCores on the wire and no diff.
func TestRTFDeployment_EchoNoWire(t *testing.T) {
	h := newRTFApplyHarness(t, resourceRTFDeployment())
	h.mock.vcores = 0.1
	res := []any{map[string]any{
		"cpu_limit": "100m", "cpu_reserved": "20m", "memory_limit": "700Mi", "memory_reserved": "700Mi",
	}}
	cfg := rtfVCoresRawConfig(0, map[string]any{"resources": res})
	state := h.apply(nil, cfg)
	if _, ok := bodyApp(h.mock.bodies[0])["vCores"]; ok {
		t.Errorf("POST must not carry vCores")
	}
	if _, paths := h.diff(state, cfg); len(paths) > 0 {
		t.Errorf("expected empty diff after create, got %v", paths)
	}
	state = h.apply(state, rtfVCoresRawConfig(0, map[string]any{"resources": res, "jvm_args": "-Xmx64m"}))
	if _, ok := bodyApp(h.mock.bodies[1])["vCores"]; ok {
		t.Errorf("PATCH must not carry vCores")
	}
	_ = state
}

// With the logging block omitted, the echoed logging service must not produce a diff.
func TestRTFDeployment_LoggingOmitted_EmptyDiff(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    func() *schema.Resource
		cfg  func() map[string]any
	}{
		{"anypoint_rtf_deployment", resourceRTFDeployment, func() map[string]any {
			cfg := rtfVCoresRawConfig(0.1, map[string]any{})
			delete(cfg["application"].([]any)[0].(map[string]any)["configuration"].([]any)[0].(map[string]any), "mule_agent_logging_service")
			return cfg
		}},
		{"anypoint_cloudhub2_shared_space_deployment", resourceCloudhub2SharedSpaceDeployment, func() map[string]any {
			cfg := rtfVCoresRawConfig(0.1, map[string]any{})
			cfg["target"].([]any)[0].(map[string]any)["target_id"] = "cloudhub-us-east-1"
			delete(cfg["application"].([]any)[0].(map[string]any)["configuration"].([]any)[0].(map[string]any), "mule_agent_logging_service")
			return cfg
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRTFApplyHarness(t, tc.r())
			cfg := tc.cfg()
			state := h.apply(nil, cfg)
			if _, ok := h.mock.bodies[0]["application"].(map[string]any)["configuration"].(map[string]any)["mule.agent.logging.service"]; ok {
				t.Errorf("POST must not carry the logging service when the block is omitted")
			}
			if got := state.Attributes["application.0.configuration.0.mule_agent_logging_service.#"]; got != "1" {
				t.Errorf("echoed logging service not in state: # = %q", got)
			}
			if _, paths := h.diff(state, cfg); len(paths) > 0 {
				t.Errorf("expected empty diff, got %v", paths)
			}
		})
	}
}

func TestFlattenApplication_VCoresRounding(t *testing.T) {
	for _, tc := range []struct {
		in   float32
		want float64
	}{{0.1, 0.1}, {0.05, 0.05}, {0.5, 0.5}, {1.5, 1.5}} {
		app := application_manager_v2.NewApplication()
		app.SetVCores(tc.in)
		if got := flattenAppDeploymentV2Application(app)["vcores"]; got != tc.want {
			t.Errorf("vcores %v flattened to %v, want %v", tc.in, got, tc.want)
		}
	}
}
