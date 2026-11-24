package anypoint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	apim "github.com/mulesoft-anypoint/anypoint-client-go/apim"
	apim_upstream "github.com/mulesoft-anypoint/anypoint-client-go/apim_upstream"
)

func TestApimFlexGatewaySchema_AssetVersionNotForceNew(t *testing.T) {
	if resourceApimFlexGateway().Schema["asset_version"].ForceNew {
		t.Fatal("asset_version must not be ForceNew")
	}
}

func TestApimFlexGatewaySchema_TagsDiffSuppress(t *testing.T) {
	if resourceApimFlexGateway().Schema["tags"].DiffSuppressFunc == nil {
		t.Fatal("tags must have a DiffSuppressFunc (case-insensitive)")
	}
}

func TestApimFlexGatewaySchema_AssetVersionUpdatable(t *testing.T) {
	for _, a := range getApimFlexGatewayUpdatableAttributes() {
		if a == "asset_version" {
			return
		}
	}
	t.Fatal("asset_version must be in the updatable attributes")
}

func TestNewApimFlexGatewayPostBody_DescriptionAndProvider(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, map[string]any{
		"description": "d",
		"provider_id": "p",
	})
	body := newApimFlexGatewayPostBody(d)
	if got := body.GetDescription(); got != "d" {
		t.Errorf("description = %q, want d", got)
	}
	if got := body.GetProviderId(); got != "p" {
		t.Errorf("provider_id = %q, want p", got)
	}

	empty := newApimFlexGatewayPostBody(schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, map[string]any{}))
	if empty.HasDescription() {
		t.Error("description must not be set when unset in config")
	}
}

// apimFlexGatewayBaseRaw returns a minimal raw config satisfying the Required
// attributes and blocks of the resource.
func apimFlexGatewayBaseRaw(assetVersion string) map[string]any {
	return map[string]any{
		"org_id":                 "org",
		"env_id":                 "env",
		"asset_group_id":         "grp",
		"asset_id":               "asset",
		"asset_version":          assetVersion,
		"deployment_target_id":   "target",
		"deployment_target_name": "target-name",
		"upstreams": []any{
			map[string]any{"label": "u", "uri": "https://example.com"},
		},
		"routing": []any{
			map[string]any{
				"label": "r",
				"upstreams": []any{
					map[string]any{"label": "u", "weight": 100},
				},
			},
		},
	}
}

// apimFlexGatewayDiffConfig builds a minimal raw config satisfying the Required
// attributes and blocks, overlaid with the given extras.
func apimFlexGatewayDiffConfig(assetVersion string, extra map[string]any) *terraform.ResourceConfig {
	raw := apimFlexGatewayBaseRaw(assetVersion)
	for k, v := range extra {
		raw[k] = v
	}
	return terraform.NewResourceConfigRaw(raw)
}

func apimFlexGatewayDiffState(assetVersion string, extra map[string]string) *terraform.InstanceState {
	attrs := map[string]string{
		"id":                     "1",
		"org_id":                 "org",
		"env_id":                 "env",
		"asset_group_id":         "grp",
		"asset_id":               "asset",
		"asset_version":          assetVersion,
		"deployment_target_id":   "target",
		"deployment_target_name": "target-name",
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return &terraform.InstanceState{ID: "1", Attributes: attrs}
}

func TestApimFlexGatewayDiff_CaseOnlyTagsNoDiff(t *testing.T) {
	state := apimFlexGatewayDiffState("1.0.0", map[string]string{"tags.#": "2", "tags.0": "mytag", "tags.1": "qa"})
	cfg := apimFlexGatewayDiffConfig("1.0.0", map[string]any{"tags": []any{"MYTAG", "QA"}})
	diff, err := resourceApimFlexGateway().Diff(context.Background(), state, cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff == nil {
		return
	}
	for k := range diff.Attributes {
		if strings.HasPrefix(k, "tags") {
			t.Errorf("case-only tag change must not produce a diff, got %q: %#v", k, diff.Attributes[k])
		}
	}
}

func TestApimFlexGatewayDiff_CaseDuplicateTagsError(t *testing.T) {
	state := apimFlexGatewayDiffState("1.0.0", nil)
	cfg := apimFlexGatewayDiffConfig("1.0.0", map[string]any{"tags": []any{"QA", "qa"}})
	_, err := resourceApimFlexGateway().Diff(context.Background(), state, cfg, nil)
	if err == nil {
		t.Fatal("expected error for case-duplicate tags")
	}
	if !strings.Contains(err.Error(), `"QA"`) || !strings.Contains(err.Error(), `"qa"`) {
		t.Errorf("error should name both tags, got %q", err)
	}
}

func TestApimFlexGatewayDiff_MajorBumpRequiresNew(t *testing.T) {
	state := apimFlexGatewayDiffState("1.0.0", nil)
	diff, err := resourceApimFlexGateway().Diff(context.Background(), state, apimFlexGatewayDiffConfig("2.0.0", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff == nil || !diff.RequiresNew() {
		t.Errorf("major bump 1.0.0 -> 2.0.0 must require replacement, got %#v", diff)
	}
	diff, err = resourceApimFlexGateway().Diff(context.Background(), state, apimFlexGatewayDiffConfig("1.0.1", nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff == nil {
		t.Fatal("expected an in-place diff for 1.0.0 -> 1.0.1")
	}
	if diff.RequiresNew() {
		t.Errorf("minor bump 1.0.0 -> 1.0.1 must update in place, got %#v", diff)
	}
}

// apimFlexGatewayChangeData builds a ResourceData whose state comes from oldRaw
// and whose planned diff comes from newRaw, as seen by Update.
func apimFlexGatewayChangeData(t *testing.T, oldRaw, newRaw map[string]any) *schema.ResourceData {
	t.Helper()
	r := resourceApimFlexGateway()
	old := schema.TestResourceDataRaw(t, r.Schema, oldRaw)
	old.SetId("1")
	state := old.State()
	if state == nil {
		t.Fatal("old state is nil")
	}
	diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(newRaw), nil)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff == nil {
		t.Fatal("expected a non-empty diff")
	}
	d, err := schema.InternalMap(r.Schema).Data(state, diff)
	if err != nil {
		t.Fatalf("data: %v", err)
	}
	return d
}

// apimPatchJSON round-trips a patch body through JSON so assertions run on the
// wire shape rather than on Go structs.
func apimPatchJSON(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

var apimFlexGatewayInboundFixture = []any{map[string]any{"secret_group_id": "sg", "tls_context_id": "tc"}}

func apimFlexGatewayRawWith(version string, extra map[string]any) map[string]any {
	raw := apimFlexGatewayBaseRaw(version)
	for k, v := range extra {
		raw[k] = v
	}
	return raw
}

func apimFlexGatewayPatchJSON(t *testing.T, oldRaw, newRaw map[string]any) map[string]any {
	t.Helper()
	return apimPatchJSON(t, newApimFlexGatewayPatchBody(apimFlexGatewayChangeData(t, oldRaw, newRaw)))
}

func assertNoEndpoint(t *testing.T, body map[string]any) {
	t.Helper()
	if _, ok := body["endpoint"]; ok {
		t.Errorf("patch body must not contain endpoint, got %#v", body["endpoint"])
	}
}

func endpointOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	ep, ok := body["endpoint"].(map[string]any)
	if !ok {
		t.Fatalf("patch body must contain an endpoint object, got %#v", body)
	}
	return ep
}

func TestApimFlexGatewayPatchBody_VersionBumpNoEndpoint(t *testing.T) {
	body := apimFlexGatewayPatchJSON(t, apimFlexGatewayBaseRaw("1.0.0"), apimFlexGatewayBaseRaw("1.0.1"))
	if body["assetVersion"] != "1.0.1" {
		t.Errorf("assetVersion = %v, want 1.0.1", body["assetVersion"])
	}
	assertNoEndpoint(t, body)
	if _, ok := body["deployment"]; !ok {
		t.Error("deployment must stay in the patch body")
	}
}

func TestApimFlexGatewayPatchBody_VersionBumpWithInboundNoEndpoint(t *testing.T) {
	extra := map[string]any{"endpoint_tls_inbound_context": apimFlexGatewayInboundFixture}
	body := apimFlexGatewayPatchJSON(t, apimFlexGatewayRawWith("1.0.0", extra), apimFlexGatewayRawWith("1.0.1", extra))
	assertNoEndpoint(t, body)
}

func TestApimFlexGatewayPatchBody_DescriptionOnlyNoEndpoint(t *testing.T) {
	body := apimFlexGatewayPatchJSON(t,
		apimFlexGatewayRawWith("1.0.0", map[string]any{"description": "a"}),
		apimFlexGatewayRawWith("1.0.0", map[string]any{"description": "b"}))
	if body["description"] != "b" {
		t.Errorf("description = %v, want b", body["description"])
	}
	assertNoEndpoint(t, body)
}

func TestApimFlexGatewayPatchBody_UpstreamOnlyNoEndpoint(t *testing.T) {
	newRaw := apimFlexGatewayBaseRaw("1.0.0")
	newRaw["upstreams"] = []any{map[string]any{"label": "u", "uri": "https://example.org"}}
	body := apimFlexGatewayPatchJSON(t, apimFlexGatewayBaseRaw("1.0.0"), newRaw)
	assertNoEndpoint(t, body)
}

func TestApimFlexGatewayPatchBody_RoutingOnlyNoEndpoint(t *testing.T) {
	newRaw := apimFlexGatewayBaseRaw("1.0.0")
	newRaw["upstreams"] = []any{
		map[string]any{"label": "u", "uri": "https://example.com"},
		map[string]any{"label": "v", "uri": "https://example.net"},
	}
	oldRaw := apimFlexGatewayBaseRaw("1.0.0")
	oldRaw["upstreams"] = newRaw["upstreams"]
	newRaw["routing"] = []any{
		map[string]any{
			"label": "r",
			"upstreams": []any{
				map[string]any{"label": "u", "weight": 60},
				map[string]any{"label": "v", "weight": 40},
			},
		},
	}
	body := apimFlexGatewayPatchJSON(t, oldRaw, newRaw)
	if _, ok := body["routing"]; !ok {
		t.Error("routing change must reach the patch body")
	}
	assertNoEndpoint(t, body)
}

func TestApimFlexGatewayPatchBody_ProxyURIChangeNoTlsContexts(t *testing.T) {
	body := apimFlexGatewayPatchJSON(t,
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_proxy_uri": "http://0.0.0.0:8081/a"}),
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_proxy_uri": "http://0.0.0.0:8081/b"}))
	ep := endpointOf(t, body)
	if ep["proxyUri"] != "http://0.0.0.0:8081/b" {
		t.Errorf("proxyUri = %v", ep["proxyUri"])
	}
	if _, ok := ep["tlsContexts"]; ok {
		t.Errorf("endpoint must not contain tlsContexts, got %#v", ep["tlsContexts"])
	}
}

func TestApimFlexGatewayPatchBody_DeploymentTypeOnlySendsEndpoint(t *testing.T) {
	body := apimFlexGatewayPatchJSON(t,
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_deployment_type": "HY"}),
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_deployment_type": "CH2"}))
	ep := endpointOf(t, body)
	if ep["deploymentType"] != "CH2" {
		t.Errorf("deploymentType = %v, want CH2", ep["deploymentType"])
	}
	if _, ok := ep["tlsContexts"]; ok {
		t.Errorf("endpoint must not contain tlsContexts, got %#v", ep["tlsContexts"])
	}
}

func TestApimFlexGatewayPatchBody_RegistrationURIOnlySendsEndpoint(t *testing.T) {
	body := apimFlexGatewayPatchJSON(t,
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_proxy_registration_uri": "http://0.0.0.0:8082/a"}),
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_proxy_registration_uri": "http://0.0.0.0:8082/b"}))
	ep := endpointOf(t, body)
	if ep["proxyRegistrationUri"] != "http://0.0.0.0:8082/b" {
		t.Errorf("proxyRegistrationUri = %v, want http://0.0.0.0:8082/b", ep["proxyRegistrationUri"])
	}
	if _, ok := ep["tlsContexts"]; ok {
		t.Errorf("endpoint must not contain tlsContexts, got %#v", ep["tlsContexts"])
	}
}

func assertInbound(t *testing.T, ep map[string]any) {
	t.Helper()
	tc, ok := ep["tlsContexts"].(map[string]any)
	if !ok {
		t.Fatalf("tlsContexts must be an object, got %#v", ep["tlsContexts"])
	}
	if _, ok := tc["outbound"]; ok {
		t.Errorf("tlsContexts must not contain outbound, got %#v", tc)
	}
	want := map[string]any{"secretGroupId": "sg", "tlsContextId": "tc"}
	got, ok := tc["inbound"].(map[string]any)
	if !ok || len(got) != len(want) || got["secretGroupId"] != "sg" || got["tlsContextId"] != "tc" {
		t.Errorf("inbound = %#v, want %#v", tc["inbound"], want)
	}
}

func TestApimFlexGatewayPatchBody_ProxyURIChangeKeepsInbound(t *testing.T) {
	body := apimFlexGatewayPatchJSON(t,
		apimFlexGatewayRawWith("1.0.0", map[string]any{
			"endpoint_proxy_uri":           "http://0.0.0.0:8081/a",
			"endpoint_tls_inbound_context": apimFlexGatewayInboundFixture,
		}),
		apimFlexGatewayRawWith("1.0.0", map[string]any{
			"endpoint_proxy_uri":           "http://0.0.0.0:8081/b",
			"endpoint_tls_inbound_context": apimFlexGatewayInboundFixture,
		}))
	assertInbound(t, endpointOf(t, body))
}

func TestApimFlexGatewayPatchBody_InboundAdded(t *testing.T) {
	body := apimFlexGatewayPatchJSON(t,
		apimFlexGatewayBaseRaw("1.0.0"),
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_tls_inbound_context": apimFlexGatewayInboundFixture}))
	assertInbound(t, endpointOf(t, body))
}

func TestApimFlexGatewayPatchBody_InboundRemoved(t *testing.T) {
	body := apimFlexGatewayPatchJSON(t,
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_tls_inbound_context": apimFlexGatewayInboundFixture}),
		apimFlexGatewayBaseRaw("1.0.0"))
	ep := endpointOf(t, body)
	tc, ok := ep["tlsContexts"].(map[string]any)
	if !ok {
		t.Fatalf("tlsContexts must be an object, got %#v", ep["tlsContexts"])
	}
	v, present := tc["inbound"]
	if len(tc) != 1 || !present || v != nil {
		t.Errorf("tlsContexts = %#v, want exactly {inbound: null}", tc)
	}
}

func TestApimFlexGatewayPatchBody_NeverNullTlsContexts(t *testing.T) {
	inbound := map[string]any{"endpoint_tls_inbound_context": apimFlexGatewayInboundFixture}
	cases := map[string][2]map[string]any{
		"version bump":         {apimFlexGatewayBaseRaw("1.0.0"), apimFlexGatewayBaseRaw("1.0.1")},
		"version bump inbound": {apimFlexGatewayRawWith("1.0.0", inbound), apimFlexGatewayRawWith("1.0.1", inbound)},
		"description": {
			apimFlexGatewayRawWith("1.0.0", map[string]any{"description": "a"}),
			apimFlexGatewayRawWith("1.0.0", map[string]any{"description": "b"}),
		},
		"proxy uri": {
			apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_proxy_uri": "http://0.0.0.0:8081/a"}),
			apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_proxy_uri": "http://0.0.0.0:8081/b"}),
		},
		"proxy uri inbound": {
			apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_proxy_uri": "http://0.0.0.0:8081/a", "endpoint_tls_inbound_context": apimFlexGatewayInboundFixture}),
			apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_proxy_uri": "http://0.0.0.0:8081/b", "endpoint_tls_inbound_context": apimFlexGatewayInboundFixture}),
		},
		"inbound added":   {apimFlexGatewayBaseRaw("1.0.0"), apimFlexGatewayRawWith("1.0.0", inbound)},
		"inbound removed": {apimFlexGatewayRawWith("1.0.0", inbound), apimFlexGatewayBaseRaw("1.0.0")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			body := apimFlexGatewayPatchJSON(t, c[0], c[1])
			ep, ok := body["endpoint"].(map[string]any)
			if !ok {
				return
			}
			if v, present := ep["tlsContexts"]; present {
				if _, isMap := v.(map[string]any); !isMap {
					t.Errorf("tlsContexts must be absent or an object, got %#v", v)
				}
			}
		})
	}
}

// apimFlexGatewayTestMeta aims the apim and apim_upstream clients at url.
func apimFlexGatewayTestMeta(url string) ProviderConfOutput {
	apimCfg := apim.NewConfiguration()
	apimCfg.Servers = apim.ServerConfigurations{{URL: url}}
	upstreamCfg := apim_upstream.NewConfiguration()
	upstreamCfg.Servers = apim_upstream.ServerConfigurations{{URL: url}}
	return ProviderConfOutput{
		access_token:       "x",
		server_index:       0,
		apimclient:         apim.NewAPIClient(apimCfg),
		apimupstreamclient: apim_upstream.NewAPIClient(upstreamCfg),
	}
}

// apimFlexGatewayClosedServerURL returns the URL of an httptest server that is
// already closed, so every call fails at transport level with a nil response.
func apimFlexGatewayClosedServerURL() string {
	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL
	ts.Close()
	return url
}

// apimFlexGatewayUpstreamChangeData is like apimFlexGatewayChangeData but the
// old state carries upstreams with server-assigned ids, as after a real apply.
func apimFlexGatewayUpstreamChangeData(t *testing.T, oldUpstreams []any, newRaw map[string]any) *schema.ResourceData {
	t.Helper()
	r := resourceApimFlexGateway()
	old := schema.TestResourceDataRaw(t, r.Schema, apimFlexGatewayBaseRaw("1.0.0"))
	old.SetId("1")
	if err := old.Set("upstreams", oldUpstreams); err != nil {
		t.Fatalf("set upstreams: %v", err)
	}
	state := old.State()
	diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(newRaw), nil)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	d, err := schema.InternalMap(r.Schema).Data(state, diff)
	if err != nil {
		t.Fatalf("data: %v", err)
	}
	return d
}

func TestApimFlexGatewayUpdate_TransportErrorNoPanic(t *testing.T) {
	oldUpstreams := []any{
		map[string]any{"id": "a", "label": "u", "uri": "https://example.com"},
		map[string]any{"id": "b", "label": "v", "uri": "https://v.example.com"},
	}
	upstreamsRaw := func(uris ...string) map[string]any {
		raw := apimFlexGatewayBaseRaw("1.0.0")
		var ups []any
		for i, uri := range uris {
			ups = append(ups, map[string]any{"label": []string{"u", "v"}[i], "uri": uri})
		}
		raw["upstreams"] = ups
		return raw
	}

	// instanceOKThenDrop answers the instance PATCH so Update reaches the
	// upstream DELETE loop, then drops every other connection mid-request.
	instanceOKThenDrop := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})

	tests := []struct {
		name    string
		summary string // the failing call must be the one under test
		data    func(t *testing.T) *schema.ResourceData
		url     func(t *testing.T) string
	}{
		{
			name:    "upstream patch",
			summary: "Unable to update Flex Gateway upstream a",
			data: func(t *testing.T) *schema.ResourceData {
				return apimFlexGatewayUpstreamChangeData(t, oldUpstreams, upstreamsRaw("https://changed.example.com", "https://v.example.com"))
			},
			url: func(t *testing.T) string { return apimFlexGatewayClosedServerURL() },
		},
		{
			name:    "instance patch",
			summary: "Unable to update Flex Gateway instance 1",
			data: func(t *testing.T) *schema.ResourceData {
				return apimFlexGatewayChangeData(t,
					apimFlexGatewayRawWith("1.0.0", map[string]any{"description": "a"}),
					apimFlexGatewayRawWith("1.0.0", map[string]any{"description": "b"}))
			},
			url: func(t *testing.T) string { return apimFlexGatewayClosedServerURL() },
		},
		{
			name:    "upstream delete",
			summary: "Unable to remove Flex Gateway upstream b",
			data: func(t *testing.T) *schema.ResourceData {
				return apimFlexGatewayUpstreamChangeData(t, oldUpstreams, upstreamsRaw("https://example.com"))
			},
			url: func(t *testing.T) string {
				ts := httptest.NewServer(instanceOKThenDrop)
				t.Cleanup(ts.Close)
				return ts.URL
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			d := tc.data(t)
			diags := resourceApimFlexGatewayUpdate(context.Background(), d, apimFlexGatewayTestMeta(tc.url(t)))
			if !diags.HasError() {
				t.Fatalf("expected an error diagnostic, got %v", diags)
			}
			if got := diagsText(diags); !strings.Contains(got, tc.summary) {
				t.Errorf("expected diagnostic %q, got:\n%s", tc.summary, got)
			}
		})
	}
}
