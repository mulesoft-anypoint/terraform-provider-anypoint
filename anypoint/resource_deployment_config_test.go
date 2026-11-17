package anypoint

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	application_manager_v2 "github.com/mulesoft-anypoint/anypoint-client-go/application_manager_v2"
)

// deploymentConfigCase describes one deployment configuration shape. Resources and
// builders are listed per resource so that the same cases run against both.
type deploymentConfigTarget struct {
	name     string
	resource func() *schema.Resource
	// build converts the configuration map (as returned by d.Get) into the API object.
	build func(map[string]any) *application_manager_v2.AppConfiguration
	// raw returns a full raw config where application.0.configuration.0 is cfg.
	raw func(cfg map[string]any) map[string]any
}

func deploymentConfigTargets() []deploymentConfigTarget {
	withConfiguration := func(cfg map[string]any) map[string]any {
		raw := rtfTestRawConfig(map[string]any{})
		raw["application"].([]any)[0].(map[string]any)["configuration"] = []any{cfg}
		return raw
	}
	withConfigurationC2SS := func(cfg map[string]any) map[string]any {
		raw := withConfiguration(cfg)
		raw["application"].([]any)[0].(map[string]any)["vcores"] = 0.1
		raw["target"].([]any)[0].(map[string]any)["target_id"] = "cloudhub-us-east-1"
		return raw
	}
	return []deploymentConfigTarget{
		{"anypoint_rtf_deployment", resourceRTFDeployment, newRTFDeploymentConfiguration, withConfiguration},
		{"anypoint_cloudhub2_shared_space_deployment", resourceCloudhub2SharedSpaceDeployment, newCloudhub2SharedSpaceDeploymentConfiguration, withConfigurationC2SS},
	}
}

func TestDeploymentConfig_Validate_PropsOmitted(t *testing.T) {
	cases := map[string]map[string]any{
		"properties empty only":   {"properties": map[string]any{}},
		"secure_properties only":  {"secure_properties": map[string]any{"k": "v"}},
		"neither map":             {},
		"properties with a value": {"properties": map[string]any{"a": "b"}},
		"both empty maps":         {"properties": map[string]any{}, "secure_properties": map[string]any{}},
		"both with values":        {"properties": map[string]any{"a": "b"}, "secure_properties": map[string]any{"k": "v"}},
	}
	for _, tgt := range deploymentConfigTargets() {
		r := tgt.resource()
		implied := r.CoreConfigSchema().ImpliedType()
		for name, props := range cases {
			t.Run(tgt.name+"/"+name, func(t *testing.T) {
				defer func() {
					if rec := recover(); rec != nil {
						t.Fatalf("Validate panicked: %v", rec)
					}
				}()
				cfg := map[string]any{
					"mule_agent_app_props_service": []any{props},
					"mule_agent_logging_service":   []any{map[string]any{}},
				}
				val := rtfTestRawValue(t, implied, tgt.raw(cfg))
				for _, d := range r.Validate(terraform.NewResourceConfigShimmed(val, r.CoreConfigSchema())) {
					if d.Severity == diag.Error {
						t.Errorf("unexpected error: %s: %s", d.Summary, d.Detail)
					}
				}
			})
		}
	}
}

// configurationFromRaw returns application.0.configuration.0 as the builders see it.
func configurationFromRaw(t *testing.T, tgt deploymentConfigTarget, cfg map[string]any) map[string]any {
	t.Helper()
	d := schema.TestResourceDataRaw(t, tgt.resource().Schema, tgt.raw(cfg))
	return d.Get("application.0.configuration.0").(map[string]any)
}

func TestDeploymentConfig_LoggingOmitted_NoPanic(t *testing.T) {
	props := []any{map[string]any{}}
	cases := []struct {
		name       string
		logging    map[string]any // nil = block omitted
		wantSvc    bool
		wantScopes int
	}{
		{"omitted", nil, false, 0},
		{"empty block", map[string]any{}, true, 0},
		{"one scope", map[string]any{"scope_logging_configurations": []any{
			map[string]any{"scope": "org.mule", "log_level": "DEBUG"},
		}}, true, 1},
	}
	for _, tgt := range deploymentConfigTargets() {
		for _, tc := range cases {
			t.Run(tgt.name+"/"+tc.name, func(t *testing.T) {
				defer func() {
					if rec := recover(); rec != nil {
						t.Fatalf("builder panicked: %v", rec)
					}
				}()
				cfg := map[string]any{"mule_agent_app_props_service": props}
				if tc.logging != nil {
					cfg["mule_agent_logging_service"] = []any{tc.logging}
				}
				got := tgt.build(configurationFromRaw(t, tgt, cfg))
				if got.HasMuleAgentLoggingService() != tc.wantSvc {
					t.Fatalf("HasMuleAgentLoggingService() = %v, want %v", got.HasMuleAgentLoggingService(), tc.wantSvc)
				}
				if tc.wantSvc {
					svc := got.GetMuleAgentLoggingService()
					if n := len(svc.GetScopeLoggingConfigurations()); n != tc.wantScopes {
						t.Errorf("scopes = %d, want %d", n, tc.wantScopes)
					}
				}
			})
		}
	}
}
