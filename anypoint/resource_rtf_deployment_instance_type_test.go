package anypoint

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

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
	body := newRTFDeploymentBody(d, sendResources)
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
