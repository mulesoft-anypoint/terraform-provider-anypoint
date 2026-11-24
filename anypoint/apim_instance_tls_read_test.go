package anypoint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	apim "github.com/mulesoft-anypoint/anypoint-client-go/apim"
)

const apimInstanceTlsAudit = `{"created":{"date":"2026-11-24T09:04:03.000Z"},"updated":{"date":"2026-11-24T09:04:51.000Z"}}`

func apimInstanceTlsContextsJSON(inbound string) string {
	return `{"audit":` + apimInstanceTlsAudit + `,"inbound":` + inbound + `,"outbound":{"secretGroupId":"sg-out","tlsContextId":"out","name":"upstream-tls","authorized":true}}`
}

// apimInstanceDetailsFromJSON builds instance details whose endpoint carries
// the given raw tlsContexts JSON (empty means the field is absent).
func apimInstanceDetailsFromJSON(t *testing.T, tlsContexts string) *apim.ApimInstanceDetails {
	t.Helper()
	ep := `{"id":1,"type":"fg","proxyUri":"http://0.0.0.0:8081/a"`
	if tlsContexts != "" {
		ep += `,"tlsContexts":` + tlsContexts
	}
	ep += `}`
	raw := `{"id":1,"organizationId":"org","environmentId":"env","endpoint":` + ep + `}`
	var details apim.ApimInstanceDetails
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		t.Fatalf("unmarshal details: %v", err)
	}
	return &details
}

func apimInstanceEndpointFromJSON(t *testing.T, tlsContexts string) *apim.Endpoint {
	t.Helper()
	d := apimInstanceDetailsFromJSON(t, tlsContexts)
	return d.Endpoint
}

const apimInboundJSON = `{"secretGroupId":"sg1","tlsContextId":"tc1","name":"in","authorized":true}`

func TestFlattenApimEndpointTlsContext_InboundOnly(t *testing.T) {
	ep := apimInstanceEndpointFromJSON(t, apimInstanceTlsContextsJSON(apimInboundJSON))
	got := flattenApimEndpointTlsContext(ep.TlsContexts)
	if got == nil {
		t.Fatal("expected an entry for a set inbound context")
	}
	want := map[string]any{"secret_group_id": "sg1", "tls_context_id": "tc1", "name": "in", "authorized": "true"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	for k, v := range got {
		if v == "out" || v == "sg-out" || v == "upstream-tls" {
			t.Errorf("outbound value leaked into inbound entry: %s=%#v", k, v)
		}
	}
}

func TestFlattenApimEndpointTlsContext_NoInboundIsNil(t *testing.T) {
	if got := flattenApimEndpointTlsContext(nil); got != nil {
		t.Errorf("nil tls contexts must flatten to nil, got %#v", got)
	}
	ep := apimInstanceEndpointFromJSON(t, apimInstanceTlsContextsJSON("null"))
	if got := flattenApimEndpointTlsContext(ep.TlsContexts); got != nil {
		t.Errorf("null inbound must flatten to nil, got %#v", got)
	}
	ep = apimInstanceEndpointFromJSON(t, `{"outbound":{"tlsContextId":"out"}}`)
	if got := flattenApimEndpointTlsContext(ep.TlsContexts); got != nil {
		t.Errorf("absent inbound must flatten to nil, got %#v", got)
	}
}

func TestFlattenApimEndpoint_OutboundOnlyGivesEmptyInbound(t *testing.T) {
	for name, tc := range map[string]string{
		"null inbound, outbound set": apimInstanceTlsContextsJSON("null"),
		"tlsContexts absent":         "",
		"tlsContexts null":           "null",
	} {
		t.Run(name, func(t *testing.T) {
			got := flattenApimEndpoint(apimInstanceEndpointFromJSON(t, tc))
			v, ok := got["endpoint_tls_inbound_context"]
			if !ok {
				t.Fatal("endpoint_tls_inbound_context key must always be present so removal shows as drift")
			}
			list, ok := v.([]map[string]any)
			if !ok {
				t.Fatalf("unexpected type %T", v)
			}
			if len(list) != 0 {
				t.Errorf("expected no inbound entries, got %#v", list)
			}
		})
	}
}

func TestApimFlexGatewaySetAttributes_InboundTlsReadBack(t *testing.T) {
	details := apimInstanceDetailsFromJSON(t, apimInstanceTlsContextsJSON(apimInboundJSON))
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, apimFlexGatewayBaseRaw("1.0.0"))
	if err := setApimFlexGatewayAttributesToResourceData(d, flattenApimInstanceDetails(details)); err != nil {
		t.Fatalf("set attributes: %v", err)
	}
	set := d.Get("endpoint_tls_inbound_context").(*schema.Set)
	if set.Len() != 1 {
		t.Fatalf("expected 1 inbound entry, got %d", set.Len())
	}
	entry := set.List()[0].(map[string]any)
	if entry["authorized"] != "true" || entry["name"] != "in" || entry["tls_context_id"] != "tc1" {
		t.Errorf("unexpected entry %#v", entry)
	}
}

func TestApimFlexGatewaySetAttributes_NoInboundClearsState(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema,
		apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_tls_inbound_context": apimFlexGatewayInboundFixture}))
	details := apimInstanceDetailsFromJSON(t, apimInstanceTlsContextsJSON("null"))
	if err := setApimFlexGatewayAttributesToResourceData(d, flattenApimInstanceDetails(details)); err != nil {
		t.Fatalf("set attributes: %v", err)
	}
	if n := d.Get("endpoint_tls_inbound_context").(*schema.Set).Len(); n != 0 {
		t.Errorf("inbound removed on the platform must clear state, got %d entries", n)
	}
}

func TestDataSourceApimInstanceSetAttributes_InboundTlsReadBack(t *testing.T) {
	details := apimInstanceDetailsFromJSON(t, apimInstanceTlsContextsJSON(apimInboundJSON))
	d := schema.TestResourceDataRaw(t, dataSourceApimInstance().Schema, map[string]any{"org_id": "org", "env_id": "env", "id": "1"})
	if err := setApimInstanceDetailsAttributesToResourceData(d, flattenApimInstanceDetails(details)); err != nil {
		t.Fatalf("set attributes: %v", err)
	}
	set := d.Get("endpoint_tls_inbound_context").(*schema.Set)
	if set.Len() != 1 {
		t.Fatalf("expected 1 inbound entry, got %d", set.Len())
	}
	entry := set.List()[0].(map[string]any)
	if entry["authorized"] != "true" || entry["secret_group_id"] != "sg1" {
		t.Errorf("unexpected entry %#v", entry)
	}

	d = schema.TestResourceDataRaw(t, dataSourceApimInstance().Schema, map[string]any{"org_id": "org", "env_id": "env", "id": "1"})
	details = apimInstanceDetailsFromJSON(t, apimInstanceTlsContextsJSON("null"))
	if err := setApimInstanceDetailsAttributesToResourceData(d, flattenApimInstanceDetails(details)); err != nil {
		t.Fatalf("set attributes: %v", err)
	}
	if n := d.Get("endpoint_tls_inbound_context").(*schema.Set).Len(); n != 0 {
		t.Errorf("outbound-only instance must give no inbound entries, got %d", n)
	}
}

// After a read, the state entry carries the computed name/authorized/audit.
// A config that only declares secret_group_id and tls_context_id must not diff.
func TestApimFlexGatewayDiff_InboundReadBackNoDiff(t *testing.T) {
	r := resourceApimFlexGateway()
	cfgRaw := apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_tls_inbound_context": []any{map[string]any{"secret_group_id": "sg1", "tls_context_id": "tc1"}}})
	old := schema.TestResourceDataRaw(t, r.Schema, apimFlexGatewayBaseRaw("1.0.0"))
	old.SetId("1")
	details := apimInstanceDetailsFromJSON(t, apimInstanceTlsContextsJSON(apimInboundJSON))
	if err := setApimFlexGatewayAttributesToResourceData(old, flattenApimInstanceDetails(details)); err != nil {
		t.Fatalf("set attributes: %v", err)
	}
	state := old.State()
	diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(cfgRaw), nil)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff == nil {
		return
	}
	for k, v := range diff.Attributes {
		if strings.HasPrefix(k, "endpoint_tls_inbound_context") {
			t.Errorf("read-back inbound must not produce a diff, got %q: %#v", k, v)
		}
	}
}

// Inbound removed outside Terraform: the next refresh empties the set and the
// plan wants to add it back.
func TestApimFlexGatewayDiff_InboundRemovedOutsideTerraform(t *testing.T) {
	r := resourceApimFlexGateway()
	cfgRaw := apimFlexGatewayRawWith("1.0.0", map[string]any{"endpoint_tls_inbound_context": apimFlexGatewayInboundFixture})
	old := schema.TestResourceDataRaw(t, r.Schema, apimFlexGatewayBaseRaw("1.0.0"))
	old.SetId("1")
	details := apimInstanceDetailsFromJSON(t, apimInstanceTlsContextsJSON("null"))
	if err := setApimFlexGatewayAttributesToResourceData(old, flattenApimInstanceDetails(details)); err != nil {
		t.Fatalf("set attributes: %v", err)
	}
	diff, err := r.Diff(context.Background(), old.State(), terraform.NewResourceConfigRaw(cfgRaw), nil)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff == nil {
		t.Fatal("expected a diff re-adding the inbound context")
	}
	found := false
	for k := range diff.Attributes {
		if strings.HasPrefix(k, "endpoint_tls_inbound_context") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected endpoint_tls_inbound_context in diff, got %#v", diff.Attributes)
	}
}

// No inbound in config, upstream TLS (outbound) on the platform: no phantom entry, no diff.
func TestApimFlexGatewayDiff_OutboundOnlyNoPhantomInbound(t *testing.T) {
	r := resourceApimFlexGateway()
	old := schema.TestResourceDataRaw(t, r.Schema, apimFlexGatewayBaseRaw("1.0.0"))
	old.SetId("1")
	details := apimInstanceDetailsFromJSON(t, apimInstanceTlsContextsJSON("null"))
	if err := setApimFlexGatewayAttributesToResourceData(old, flattenApimInstanceDetails(details)); err != nil {
		t.Fatalf("set attributes: %v", err)
	}
	diff, err := r.Diff(context.Background(), old.State(), terraform.NewResourceConfigRaw(apimFlexGatewayBaseRaw("1.0.0")), nil)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff == nil {
		return
	}
	for k, v := range diff.Attributes {
		if strings.HasPrefix(k, "endpoint_tls_inbound_context") {
			t.Errorf("unexpected inbound diff %q: %#v", k, v)
		}
	}
}

// tlsQueryRecorder serves a minimal instance for any GET and records the queries of instance GETs.
type tlsQueryRecorder struct {
	mu      sync.Mutex
	queries []string
}

func (r *tlsQueryRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(req.URL.Path, "/apis/1") {
			r.mu.Lock()
			r.queries = append(r.queries, req.URL.RawQuery)
			r.mu.Unlock()
			_, _ = w.Write([]byte(`{"id":1,"organizationId":"org","environmentId":"env","endpoint":{"id":1,"tlsContexts":` + apimInstanceTlsContextsJSON(apimInboundJSON) + `}}`))
			return
		}
		_, _ = w.Write([]byte(`{"upstreams":[],"total":0}`))
	})
}

func (r *tlsQueryRecorder) assertIncludeTls(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queries) == 0 {
		t.Fatal("instance GET was never called")
	}
	for _, q := range r.queries {
		if !strings.Contains(q, "includeTlsContexts=true") {
			t.Errorf("instance GET query = %q, want includeTlsContexts=true", q)
		}
	}
}

func TestApimFlexGatewayRead_RequestsTlsContexts(t *testing.T) {
	rec := &tlsQueryRecorder{}
	ts := httptest.NewServer(rec.handler())
	defer ts.Close()
	d := schema.TestResourceDataRaw(t, resourceApimFlexGateway().Schema, apimFlexGatewayBaseRaw("1.0.0"))
	d.SetId("1")
	_ = resourceApimFlexGatewayRead(context.Background(), d, apimFlexGatewayTestMeta(ts.URL))
	rec.assertIncludeTls(t)
	if n := d.Get("endpoint_tls_inbound_context").(*schema.Set).Len(); n != 1 {
		t.Errorf("expected inbound read back into state, got %d entries", n)
	}
}

func TestDataSourceApimInstanceRead_RequestsTlsContexts(t *testing.T) {
	rec := &tlsQueryRecorder{}
	ts := httptest.NewServer(rec.handler())
	defer ts.Close()
	d := schema.TestResourceDataRaw(t, dataSourceApimInstance().Schema, map[string]any{"org_id": "org", "env_id": "env", "id": "1"})
	_ = dataSourceApimInstanceRead(context.Background(), d, apimFlexGatewayTestMeta(ts.URL))
	rec.assertIncludeTls(t)
}
