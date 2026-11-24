package anypoint

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func mqBodyJSON(t *testing.T, body any) map[string]any {
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

func mqNoneSet(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = false
	}
	return m
}

func mqAllSet(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

var amqOptionalKeys = []string{"default_ttl", "default_lock_ttl", "default_delivery_delay", "encrypted"}

func TestAttrsSetInRawConfig(t *testing.T) {
	raw := cty.ObjectVal(map[string]cty.Value{
		"default_ttl": cty.NumberIntVal(5),
		"encrypted":   cty.NullVal(cty.Bool),
	})
	got := attrsSetInRawConfig(raw, "default_ttl", "encrypted", "absent")
	want := map[string]bool{"default_ttl": true, "encrypted": false, "absent": false}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %v, want %v", k, got[k], v)
		}
	}
	for _, in := range []cty.Value{cty.NilVal, cty.NullVal(cty.EmptyObject), cty.UnknownVal(cty.EmptyObject)} {
		for k, v := range attrsSetInRawConfig(in, "default_ttl", "encrypted") {
			if v {
				t.Errorf("%s should be false for %#v", k, in)
			}
		}
	}
	for _, in := range []cty.Value{cty.StringVal("x"), cty.ListValEmpty(cty.String)} {
		for k, v := range attrsSetInRawConfig(in, "default_ttl", "encrypted") {
			if v {
				t.Errorf("%s should be false for non-object %#v", k, in)
			}
		}
	}
	unknownAttr := cty.ObjectVal(map[string]cty.Value{"encrypted": cty.UnknownVal(cty.Bool)})
	if attrsSetInRawConfig(unknownAttr, "encrypted")["encrypted"] {
		t.Error("unknown attribute must not count as set")
	}
}

func TestNewAMQCreateBody_CreateUnsetOmitsFields(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAMQ().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "queue_id": "q",
	})
	got := mqBodyJSON(t, newAMQCreateBody(d, mqNoneSet(amqOptionalKeys...), false))
	for _, k := range []string{"defaultTtl", "defaultLockTtl", "defaultDeliveryDelay", "encrypted"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s must be omitted when unset, body: %v", k, got)
		}
	}
}

func TestNewAMQCreateBody_CreateExplicitValues(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAMQ().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "queue_id": "q",
		"default_ttl": 60000, "encrypted": false, "default_delivery_delay": 0,
	})
	inConfig := map[string]bool{"default_ttl": true, "encrypted": true, "default_delivery_delay": true}
	got := mqBodyJSON(t, newAMQCreateBody(d, inConfig, false))
	if v, ok := got["defaultTtl"]; !ok || v.(float64) != 60000 {
		t.Errorf("defaultTtl: %v", got)
	}
	if v, ok := got["encrypted"]; !ok || v.(bool) != false {
		t.Errorf("encrypted: %v", got)
	}
	if v, ok := got["defaultDeliveryDelay"]; !ok || v.(float64) != 0 {
		t.Errorf("defaultDeliveryDelay: %v", got)
	}
	if _, ok := got["defaultLockTtl"]; ok {
		t.Errorf("defaultLockTtl must be omitted: %v", got)
	}
}

func TestNewAMQCreateBody_UpdateKeepsStateValues(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAMQ().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "queue_id": "q",
		"default_ttl": 604800000, "default_lock_ttl": 120000, "encrypted": true,
		"default_delivery_delay": 0,
	})
	got := mqBodyJSON(t, newAMQCreateBody(d, mqNoneSet(amqOptionalKeys...), true))
	if got["defaultTtl"] != float64(604800000) {
		t.Errorf("defaultTtl: %v", got)
	}
	if got["defaultLockTtl"] != float64(120000) {
		t.Errorf("defaultLockTtl: %v", got)
	}
	if got["encrypted"] != true {
		t.Errorf("encrypted: %v", got)
	}
	if _, ok := got["defaultDeliveryDelay"]; ok {
		t.Errorf("defaultDeliveryDelay=0 in state must be omitted: %v", got)
	}
}

func TestNewAMQCreateBody_UpdateConfigWinsOverState(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAMQ().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "queue_id": "q",
		"default_ttl": 1000, "encrypted": false,
	})
	got := mqBodyJSON(t, newAMQCreateBody(d, mqAllSet("default_ttl", "encrypted"), true))
	if got["defaultTtl"] != float64(1000) || got["encrypted"] != false {
		t.Errorf("config values must be sent: %v", got)
	}
}

func TestNewAMECreateBody_CreateUnsetOmitsEncrypted(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAME().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "exchange_id": "x",
	})
	got := mqBodyJSON(t, newAMECreateBody(d, mqNoneSet("encrypted"), false))
	if _, ok := got["encrypted"]; ok {
		t.Errorf("encrypted must be omitted when unset: %v", got)
	}
}

func TestNewAMECreateBody_CreateExplicitFalse(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAME().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "exchange_id": "x", "encrypted": false,
	})
	got := mqBodyJSON(t, newAMECreateBody(d, mqAllSet("encrypted"), false))
	if v, ok := got["encrypted"]; !ok || v != false {
		t.Errorf("explicit false must be sent: %v", got)
	}
}

func TestNewAMECreateBody_UpdateKeepsStateEncrypted(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAME().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "exchange_id": "x", "encrypted": true,
	})
	got := mqBodyJSON(t, newAMECreateBody(d, mqNoneSet("encrypted"), true))
	if got["encrypted"] != true {
		t.Errorf("state encrypted must be kept on update: %v", got)
	}
}

func assertOptionalComputedNoDefault(t *testing.T, s map[string]*schema.Schema, keys ...string) {
	t.Helper()
	for _, k := range keys {
		a, ok := s[k]
		if !ok {
			t.Fatalf("attribute %s missing", k)
		}
		if !a.Optional || !a.Computed || a.Default != nil {
			t.Errorf("%s: optional=%v computed=%v default=%v, want Optional+Computed without default", k, a.Optional, a.Computed, a.Default)
		}
	}
}

func TestAMQSchema_OptionalComputed(t *testing.T) {
	assertOptionalComputedNoDefault(t, resourceAMQ().Schema, amqOptionalKeys...)
}

func TestAMESchema_EncryptedOptionalComputed(t *testing.T) {
	assertOptionalComputedNoDefault(t, resourceAME().Schema, "encrypted")
}

// mqDiffAgainstBroker builds state as Read would leave it, then diffs an
// unrelated config that leaves the broker-populated attributes unset.
func mqDiffAgainstBroker(t *testing.T, r *schema.Resource, stateRaw, configRaw map[string]any) *terraform.InstanceDiff {
	t.Helper()
	st := schema.TestResourceDataRaw(t, r.Schema, stateRaw)
	st.SetId("o/e/us-east-1/x")
	state := st.State()
	if state == nil {
		t.Fatal("nil state")
	}
	diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(configRaw), nil)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	return diff
}

func TestAMQDiff_UnsetFieldsWithBrokerValuesNoDiff(t *testing.T) {
	ids := map[string]any{"org_id": "o", "env_id": "e", "region_id": "us-east-1", "queue_id": "x"}
	state := map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "queue_id": "x",
		"encrypted": true, "default_ttl": 604800000, "default_lock_ttl": 120000, "default_delivery_delay": 0,
	}
	diff := mqDiffAgainstBroker(t, resourceAMQ(), state, ids)
	if diff == nil {
		return
	}
	for _, k := range amqOptionalKeys {
		if a, ok := diff.Attributes[k]; ok {
			t.Errorf("unexpected diff on %s: %q -> %q", k, a.Old, a.New)
		}
	}
}

func TestAMEDiff_UnsetEncryptedWithBrokerValueNoDiff(t *testing.T) {
	ids := map[string]any{"org_id": "o", "env_id": "e", "region_id": "us-east-1", "exchange_id": "x"}
	state := map[string]any{"org_id": "o", "env_id": "e", "region_id": "us-east-1", "exchange_id": "x", "encrypted": true}
	diff := mqDiffAgainstBroker(t, resourceAME(), state, ids)
	if diff == nil {
		return
	}
	if a, ok := diff.Attributes["encrypted"]; ok {
		t.Errorf("unexpected diff on encrypted: %q -> %q", a.Old, a.New)
	}
}

func TestNewAMQCreateBody_UpdateResendsFalseEncryptedFromState(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAMQ().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "queue_id": "q", "encrypted": false,
	})
	got := mqBodyJSON(t, newAMQCreateBody(d, mqNoneSet(amqOptionalKeys...), true))
	if v, ok := got["encrypted"]; !ok || v != false {
		t.Errorf("encrypted=false in state must be re-sent on update: %v", got)
	}
}

func TestNewAMECreateBody_UpdateResendsFalseEncryptedFromState(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAME().Schema, map[string]any{
		"org_id": "o", "env_id": "e", "region_id": "us-east-1", "exchange_id": "x", "encrypted": false,
	})
	got := mqBodyJSON(t, newAMECreateBody(d, mqNoneSet("encrypted"), true))
	if v, ok := got["encrypted"]; !ok || v != false {
		t.Errorf("encrypted=false in state must be re-sent on update: %v", got)
	}
}
