package anypoint

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	application_manager_v2 "github.com/mulesoft-anypoint/anypoint-client-go/application_manager_v2"
)

// rtfTestRawConfig builds the raw config map for resourceRTFDeployment().
// deploymentSettings is merged into target.0.deployment_settings.0.
func rtfTestRawConfig(deploymentSettings map[string]any) map[string]any {
	return map[string]any{
		"org_id": "org",
		"env_id": "env",
		"name":   "app",
		"application": []any{map[string]any{
			"ref": []any{map[string]any{
				"group_id":    "g",
				"artifact_id": "a",
				"version":     "1.0.0",
				"packaging":   "jar",
			}},
			"configuration": []any{map[string]any{
				"mule_agent_app_props_service": []any{map[string]any{}},
				"mule_agent_logging_service":   []any{map[string]any{}},
			}},
		}},
		"target": []any{map[string]any{
			"target_id":           "ps-id",
			"deployment_settings": []any{deploymentSettings},
		}},
	}
}

func rtfTestResources() []any {
	return []any{map[string]any{
		"cpu_limit":       "500m",
		"cpu_reserved":    "500m",
		"memory_limit":    "700Mi",
		"memory_reserved": "700Mi",
	}}
}

// rtfTestDeploymentSettingsJSON marshals the body and returns target.deploymentSettings as a map.
func rtfTestDeploymentSettingsJSON(t *testing.T, ds map[string]any, sendResources bool) map[string]any {
	t.Helper()
	d := schema.TestResourceDataRaw(t, resourceRTFDeployment().Schema, rtfTestRawConfig(ds))
	body := newRTFDeploymentBody(d, sendResources, false)
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	target, ok := out["target"].(map[string]any)
	if !ok {
		t.Fatalf("body has no target: %s", raw)
	}
	settings, ok := target["deploymentSettings"].(map[string]any)
	if !ok {
		t.Fatalf("target has no deploymentSettings: %s", raw)
	}
	return settings
}

func TestNewRTFDeploymentBody_InstanceTypeOnly(t *testing.T) {
	settings := rtfTestDeploymentSettingsJSON(t, map[string]any{"instance_type": "mule.nano"}, false)
	if got := settings["instanceType"]; got != "mule.nano" {
		t.Errorf("instanceType = %v, want mule.nano", got)
	}
	if _, ok := settings["resources"]; ok {
		t.Errorf("resources key must be absent, got %v", settings["resources"])
	}
}

func TestNewRTFDeploymentBody_ResourcesOnly(t *testing.T) {
	settings := rtfTestDeploymentSettingsJSON(t, map[string]any{"resources": rtfTestResources()}, true)
	resources, ok := settings["resources"].(map[string]any)
	if !ok {
		t.Fatalf("resources key missing: %v", settings)
	}
	cpu, _ := resources["cpu"].(map[string]any)
	if cpu["limit"] != "500m" {
		t.Errorf("resources.cpu.limit = %v, want 500m", cpu["limit"])
	}
	if _, ok := settings["instanceType"]; ok {
		t.Errorf("instanceType key must be absent, got %v", settings["instanceType"])
	}
}

func TestNewRTFDeploymentBody_Both(t *testing.T) {
	settings := rtfTestDeploymentSettingsJSON(t, map[string]any{
		"instance_type": "mule.nano",
		"resources":     rtfTestResources(),
	}, true)
	if settings["instanceType"] != "mule.nano" {
		t.Errorf("instanceType = %v, want mule.nano", settings["instanceType"])
	}
	if _, ok := settings["resources"]; !ok {
		t.Errorf("resources key missing: %v", settings)
	}
}

// State may carry resources echoed by the API (Computed) while the user's
// config has no resources block: sendResources=false must omit the key.
func TestNewRTFDeploymentBody_ResourcesFromRawConfigOnly(t *testing.T) {
	settings := rtfTestDeploymentSettingsJSON(t, map[string]any{
		"instance_type": "mule.micro",
		"resources":     rtfTestResources(),
	}, false)
	if _, ok := settings["resources"]; ok {
		t.Errorf("resources key must be absent when sendResources=false, got %v", settings["resources"])
	}
	if settings["instanceType"] != "mule.micro" {
		t.Errorf("instanceType = %v, want mule.micro", settings["instanceType"])
	}
}

func TestRTFResourcesInRawConfig(t *testing.T) {
	resObj := cty.ObjectVal(map[string]cty.Value{
		"cpu_limit": cty.StringVal("500m"),
	})
	resType := cty.Object(map[string]cty.Type{"cpu_limit": cty.String})
	settings := func(resources cty.Value) cty.Value {
		return cty.ObjectVal(map[string]cty.Value{
			"deployment_settings": cty.ListVal([]cty.Value{
				cty.ObjectVal(map[string]cty.Value{"resources": resources}),
			}),
		})
	}
	root := func(target cty.Value) cty.Value {
		return cty.ObjectVal(map[string]cty.Value{"target": target})
	}
	settingsType := cty.Object(map[string]cty.Type{
		"deployment_settings": cty.List(cty.Object(map[string]cty.Type{
			"resources": cty.List(resType),
		})),
	})

	tests := []struct {
		name string
		raw  cty.Value
		want bool
	}{
		{"null object", cty.NullVal(cty.Object(map[string]cty.Type{})), false},
		{"unknown object", cty.UnknownVal(cty.Object(map[string]cty.Type{})), false},
		{"no target attribute", cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("x")}), false},
		{"null resources list", root(cty.ListVal([]cty.Value{settings(cty.NullVal(cty.List(resType)))})), false},
		{"empty resources list", root(cty.ListVal([]cty.Value{settings(cty.ListValEmpty(resType))})), false},
		{"one resources element", root(cty.ListVal([]cty.Value{settings(cty.ListVal([]cty.Value{resObj}))})), true},
		{"empty target list", root(cty.ListValEmpty(settingsType)), false},
		{"null target list", root(cty.NullVal(cty.List(settingsType))), false},
		{"unknown target list", root(cty.UnknownVal(cty.List(settingsType))), false},
		{"unknown resources list", root(cty.ListVal([]cty.Value{settings(cty.UnknownVal(cty.List(resType)))})), false},
		{"unknown deployment_settings", root(cty.ListVal([]cty.Value{cty.ObjectVal(map[string]cty.Value{
			"deployment_settings": cty.UnknownVal(cty.List(cty.Object(map[string]cty.Type{"resources": cty.List(resType)}))),
		})})), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rtfResourcesInRawConfig(tc.raw); got != tc.want {
				t.Errorf("rtfResourcesInRawConfig() = %v, want %v", got, tc.want)
			}
		})
	}

	// Pin the helper to the real schema shape (CoreConfigSchema implied type),
	// not only to hand-built objects.
	implied := resourceRTFDeployment().CoreConfigSchema().ImpliedType()
	for _, tc := range []struct {
		name      string
		resources []any
		want      bool
	}{
		{"real schema, one resources element", rtfTestResources(), true},
		{"real schema, empty resources list (absent block)", []any{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := rtfTestRawValue(t, implied, rtfTestRawConfig(map[string]any{"resources": tc.resources}))
			if got := rtfResourcesInRawConfig(raw); got != tc.want {
				t.Errorf("rtfResourcesInRawConfig() = %v, want %v", got, tc.want)
			}
		})
	}
}

// rtfTestRawValue converts a Go config map into a cty value conforming to typ.
// Attributes missing from cfg become null of their type.
func rtfTestRawValue(t *testing.T, typ cty.Type, cfg any) cty.Value {
	t.Helper()
	if cfg == nil {
		return cty.NullVal(typ)
	}
	switch {
	case typ.IsObjectType():
		m := cfg.(map[string]any)
		attrs := make(map[string]cty.Value)
		for name, at := range typ.AttributeTypes() {
			attrs[name] = rtfTestRawValue(t, at, m[name])
		}
		return cty.ObjectVal(attrs)
	case typ.IsListType():
		items := cfg.([]any)
		if len(items) == 0 {
			return cty.ListValEmpty(typ.ElementType())
		}
		vals := make([]cty.Value, len(items))
		for i, item := range items {
			vals[i] = rtfTestRawValue(t, typ.ElementType(), item)
		}
		return cty.ListVal(vals)
	case typ.IsMapType():
		m := cfg.(map[string]any)
		if len(m) == 0 {
			return cty.MapValEmpty(typ.ElementType())
		}
		vals := make(map[string]cty.Value)
		for k, v := range m {
			vals[k] = rtfTestRawValue(t, typ.ElementType(), v)
		}
		return cty.MapVal(vals)
	case typ == cty.String:
		return cty.StringVal(cfg.(string))
	case typ == cty.Number:
		if f, ok := cfg.(float64); ok {
			return cty.NumberFloatVal(f)
		}
		return cty.NumberIntVal(int64(cfg.(int)))
	case typ == cty.Bool:
		return cty.BoolVal(cfg.(bool))
	}
	t.Fatalf("unsupported type %s", typ.FriendlyName())
	return cty.NilVal
}

func TestFlattenDeplSett_InstanceTypeSetsOnAllSchemas(t *testing.T) {
	settings := application_manager_v2.NewDeploymentSettings()
	settings.SetInstanceType("mule.nano")
	target := application_manager_v2.NewTarget()
	target.SetDeploymentSettings(*settings)
	deployment := application_manager_v2.NewDeployment()
	deployment.SetTarget(*target)

	schemas := map[string]map[string]*schema.Schema{
		"anypoint_rtf_deployment":                    resourceRTFDeployment().Schema,
		"anypoint_cloudhub2_shared_space_deployment": resourceCloudhub2SharedSpaceDeployment().Schema,
		"data.anypoint_app_deployment_v2":            dataSourceAppDeploymentV2().Schema,
	}
	for name, s := range schemas {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, s, map[string]any{})
			data := flattenAppDeploymentV2(deployment)
			if err := setAppDeploymentV2AttributesToResourceData(d, data); err != nil {
				t.Fatalf("set attributes: %v", err)
			}
			if got := d.Get("target.0.deployment_settings.0.instance_type"); got != "mule.nano" {
				t.Errorf("target.0.deployment_settings.0.instance_type = %v, want mule.nano", got)
			}
		})
	}
}

func TestRTFDeploymentSchema_InstanceTypeAndResources(t *testing.T) {
	ds := DeplTargetDeploymentSettingsRTFDefinition.Schema
	it, ok := ds["instance_type"]
	if !ok {
		t.Fatal("instance_type missing from RTF deployment_settings schema")
	}
	if !it.Optional || !it.Computed || it.Required || it.ForceNew {
		t.Errorf("instance_type must be Optional+Computed, not Required/ForceNew: %+v", it)
	}
	res := ds["resources"]
	if !res.Optional || !res.Computed || res.Required {
		t.Errorf("resources must be Optional+Computed, not Required: Optional=%v Computed=%v Required=%v", res.Optional, res.Computed, res.Required)
	}
}

// rtfMockAppManager answers the Application Manager endpoints used by the RTF
// deployment resource and records the POST/PATCH request bodies.
type rtfMockAppManager struct {
	mu           sync.Mutex
	instanceType string
	vcores       float64          // echoed as application.vCores when > 0; sticky across a PATCH that omits it
	targetID     string           // echoed target.targetId; defaults to "ps-id"
	scopes       []any            // echoed logging scopes
	bodies       []map[string]any // POST then PATCH bodies, in order
}

func (m *rtfMockAppManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodPost, http.MethodPatch:
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		m.bodies = append(m.bodies, body)
		if app, ok := body["application"].(map[string]any); ok {
			if v, ok := app["vCores"].(float64); ok {
				m.vcores = v
			}
			if cfg, ok := app["configuration"].(map[string]any); ok {
				if svc, ok := cfg["mule.agent.logging.service"].(map[string]any); ok {
					m.scopes, _ = svc["scopeLoggingConfigurations"].([]any)
				}
			}
		}
		if target, ok := body["target"].(map[string]any); ok {
			if ds, ok := target["deploymentSettings"].(map[string]any); ok {
				if it, ok := ds["instanceType"].(string); ok {
					m.instanceType = it
				}
			}
			if id, ok := target["targetId"].(string); ok {
				m.targetID = id
			}
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"dep-1"}`))
	case http.MethodGet:
		// The platform echoes resources for instance-type sizing, and vCores once set.
		scopes := m.scopes
		if scopes == nil {
			scopes = []any{}
		}
		targetID := m.targetID
		if targetID == "" {
			targetID = "ps-id"
		}
		resp := map[string]any{
			"id":       "dep-1",
			"name":     "app",
			"replicas": []any{},
			"application": map[string]any{
				"desiredState": "STARTED",
				"ref":          map[string]any{"groupId": "g", "artifactId": "a", "version": "1.0.0", "packaging": "jar"},
				"configuration": map[string]any{
					"mule.agent.application.properties.service": map[string]any{
						"applicationName":  "app",
						"properties":       map[string]any{},
						"secureProperties": map[string]any{},
					},
					"mule.agent.logging.service": map[string]any{
						"artifactName":               "app",
						"scopeLoggingConfigurations": scopes,
					},
				},
			},
			"target": map[string]any{
				"provider": "MC",
				"targetId": targetID,
				"replicas": 1,
				"deploymentSettings": map[string]any{
					"instanceType":   m.instanceType,
					"updateStrategy": "rolling",
					"resources": map[string]any{
						"cpu":    map[string]any{"limit": "100m", "reserved": "20m"},
						"memory": map[string]any{"limit": "700Mi", "reserved": "700Mi"},
					},
				},
			},
		}
		if m.vcores > 0 {
			resp["application"].(map[string]any)["vCores"] = m.vcores
		}
		_ = json.NewEncoder(w).Encode(resp)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Drives the real Create and Update through Resource.Apply against a mock API:
// create with instance_type and no resources, then resize while state carries
// the echoed resources. Neither request may carry a resources key.
func TestRTFDeployment_CreateUpdateRequestBodies(t *testing.T) {
	mock := &rtfMockAppManager{}
	ts := httptest.NewServer(mock)
	defer ts.Close()

	cfg := application_manager_v2.NewConfiguration()
	cfg.Servers = application_manager_v2.ServerConfigurations{{URL: ts.URL}}
	meta := ProviderConfOutput{
		access_token:     "x",
		server_index:     0,
		appmanagerclient: application_manager_v2.NewAPIClient(cfg),
	}

	r := resourceRTFDeployment()
	implied := r.CoreConfigSchema().ImpliedType()
	ctx := context.Background()

	apply := func(state *terraform.InstanceState, instanceType string) *terraform.InstanceState {
		t.Helper()
		rawCfg := rtfTestRawConfig(map[string]any{"instance_type": instanceType})
		diff, err := r.Diff(ctx, state, terraform.NewResourceConfigRaw(rawCfg), meta)
		if err != nil {
			t.Fatalf("diff: %v", err)
		}
		if diff == nil {
			t.Fatal("expected a diff")
		}
		// The SDK populates this from the plan in ApplyResourceChange.
		diff.RawConfig = rtfTestRawValue(t, implied, rawCfg)
		newState, diags := r.Apply(ctx, state, diff, meta)
		if diags.HasError() {
			t.Fatalf("apply: %v", diags)
		}
		return newState
	}

	state := apply(nil, "mule.nano")
	if state == nil || state.ID != "dep-1" {
		t.Fatalf("create did not produce state with id dep-1: %+v", state)
	}
	if got := state.Attributes["target.0.deployment_settings.0.resources.#"]; got != "1" {
		t.Fatalf("expected echoed resources in state after create, got resources.# = %q", got)
	}
	apply(state, "mule.micro")

	if len(mock.bodies) != 2 {
		t.Fatalf("expected POST and PATCH bodies, got %d", len(mock.bodies))
	}
	for i, want := range []string{"mule.nano", "mule.micro"} {
		ds := mock.bodies[i]["target"].(map[string]any)["deploymentSettings"].(map[string]any)
		if ds["instanceType"] != want {
			t.Errorf("request %d instanceType = %v, want %s", i, ds["instanceType"], want)
		}
		if _, ok := ds["resources"]; ok {
			t.Errorf("request %d must not carry resources, got %v", i, ds["resources"])
		}
	}
}
