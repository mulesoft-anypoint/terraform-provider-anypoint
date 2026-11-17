package anypoint

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	private_space "github.com/mulesoft-anypoint/anypoint-client-go/private_space"
)

func TestTGWSchema_InternalValidate(t *testing.T) {
	if err := resourcePrivateSpaceTransitGateway().InternalValidate(nil, true); err != nil {
		t.Fatalf("InternalValidate: %v", err)
	}
}

func tgwTestBase(extra map[string]any) map[string]any {
	cfg := map[string]any{
		"org_id":           "org",
		"private_space_id": "ps",
		"routes":           []any{"10.0.0.0/16"},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func TestTGWSchema_Validate(t *testing.T) {
	tests := []struct {
		name    string
		extra   map[string]any
		wantErr bool
	}{
		{"create mode", map[string]any{"name": "n", "resource_share_id": "share", "resource_share_account": "123456789012"}, false},
		{"attach mode", map[string]any{"transit_gateway_id": "tgw-0abc"}, false},
		{"both transit_gateway_id and resource_share_id", map[string]any{"transit_gateway_id": "tgw-0abc", "resource_share_id": "share", "resource_share_account": "123456789012"}, true},
		{"neither mode", map[string]any{}, true},
		{"attach plus name", map[string]any{"transit_gateway_id": "tgw-0abc", "name": "n"}, true},
		{"attach plus resource_share_account", map[string]any{"transit_gateway_id": "tgw-0abc", "resource_share_account": "123456789012"}, true},
		{"share without name", map[string]any{"resource_share_id": "share", "resource_share_account": "123456789012"}, true},
		{"share without account", map[string]any{"name": "n", "resource_share_id": "share"}, true},
		{"empty transit_gateway_id", map[string]any{"transit_gateway_id": ""}, true},
		{"malformed transit_gateway_id", map[string]any{"transit_gateway_id": "sg-123"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			diags := resourcePrivateSpaceTransitGateway().Validate(terraform.NewResourceConfigRaw(tgwTestBase(tc.extra)))
			if got := diags.HasError(); got != tc.wantErr {
				t.Errorf("HasError() = %v, want %v (diags: %v)", got, tc.wantErr, diags)
			}
		})
	}
}

// tgwTestRaw builds a raw config value of the resource schema: attributes in
// strs become strings, every other attribute is null.
func tgwTestRaw(strs map[string]string) cty.Value {
	typ := resourcePrivateSpaceTransitGateway().CoreConfigSchema().ImpliedType()
	attrs := map[string]cty.Value{}
	for name, at := range typ.AttributeTypes() {
		if s, ok := strs[name]; ok {
			attrs[name] = cty.StringVal(s)
		} else {
			attrs[name] = cty.NullVal(at)
		}
	}
	return cty.ObjectVal(attrs)
}

func TestTGWModeFromRawConfig(t *testing.T) {
	tests := []struct {
		name         string
		cfg          map[string]string
		wantAttach   bool
		wantID       string
		wantConflict []string
	}{
		{"attach no conflicts", map[string]string{"transit_gateway_id": "tgw-0abc"}, true, "tgw-0abc", nil},
		{"attach plus name", map[string]string{"transit_gateway_id": "tgw-0abc", "name": "n"}, true, "tgw-0abc", []string{"name"}},
		{"attach plus all", map[string]string{"transit_gateway_id": "tgw-0abc", "name": "n", "resource_share_id": "s", "resource_share_account": "a"}, true, "tgw-0abc", []string{"name", "resource_share_id", "resource_share_account"}},
		{"create mode", map[string]string{"name": "n", "resource_share_id": "s", "resource_share_account": "a"}, false, "", []string{"name", "resource_share_id", "resource_share_account"}},
		{"empty transit_gateway_id", map[string]string{"transit_gateway_id": "", "name": "n"}, false, "", []string{"name"}},
		{"nothing", map[string]string{}, false, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attach, id, conflicting := tgwModeFromRawConfig(tgwTestRaw(tc.cfg))
			if attach != tc.wantAttach || id != tc.wantID || !reflect.DeepEqual(conflicting, tc.wantConflict) {
				t.Errorf("got (%v, %q, %v), want (%v, %q, %v)", attach, id, conflicting, tc.wantAttach, tc.wantID, tc.wantConflict)
			}
		})
	}
}

func TestTGWModeFromRawConfig_UnknownAndNull(t *testing.T) {
	typ := resourcePrivateSpaceTransitGateway().CoreConfigSchema().ImpliedType()
	attrs := map[string]cty.Value{}
	for name, at := range typ.AttributeTypes() {
		attrs[name] = cty.NullVal(at)
	}
	attrs["transit_gateway_id"] = cty.UnknownVal(cty.String)
	attach, id, conflicting := tgwModeFromRawConfig(cty.ObjectVal(attrs))
	if !attach || id != "" || len(conflicting) != 0 {
		t.Errorf("unknown id: got (%v, %q, %v), want (true, \"\", [])", attach, id, conflicting)
	}
	if attach, _, _ := tgwModeFromRawConfig(cty.NullVal(typ)); attach {
		t.Error("null raw config must not be attach mode")
	}
}

func tgwTestAttachment(status, space string) private_space.TransitGateway {
	st := private_space.NewTransitGatewayStatus()
	if status != "" {
		st.SetAttachment(status)
	}
	spec := private_space.NewTransitGatewaySpec()
	spec.SetSpaceName(space)
	att := private_space.NewTransitGateway()
	att.SetStatus(*st)
	att.SetSpec(*spec)
	return *att
}

func TestTGWLiveAttachments(t *testing.T) {
	tests := []struct {
		name string
		atts []private_space.TransitGateway
		want int
	}{
		{"empty", nil, 0},
		{"detached only", []private_space.TransitGateway{tgwTestAttachment("detached", "a")}, 0},
		{"refreshing", []private_space.TransitGateway{tgwTestAttachment("refreshing", "a")}, 1},
		{"pending", []private_space.TransitGateway{tgwTestAttachment("pending", "a")}, 1},
		{"empty status", []private_space.TransitGateway{tgwTestAttachment("", "a")}, 1},
		{"available and detached", []private_space.TransitGateway{tgwTestAttachment("available", "a"), tgwTestAttachment("detached", "b")}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tgw := private_space.NewTransitGateway()
			tgw.SetAttachments(tc.atts)
			if got := len(tgwLiveAttachments(*tgw)); got != tc.want {
				t.Errorf("len(tgwLiveAttachments) = %d, want %d", got, tc.want)
			}
		})
	}
}

func tgwTestOrgEntry(id, name, shareID string) private_space.TransitGateway {
	share := private_space.NewTransitGatewaySpecResourceShare()
	share.SetId(shareID)
	spec := private_space.NewTransitGatewaySpec()
	spec.SetResourceShare(*share)
	tgw := private_space.NewTransitGateway()
	tgw.SetId(id)
	tgw.SetName(name)
	tgw.SetSpec(*spec)
	return *tgw
}

func TestFindOrgTGWByShare(t *testing.T) {
	list := []private_space.TransitGateway{
		tgwTestOrgEntry("tgw-1", "one", "share-1"),
		tgwTestOrgEntry("tgw-2", "two", "share-2"),
	}
	if got, ok := findOrgTGWByShare(list, "share-2"); !ok || got.GetId() != "tgw-2" {
		t.Errorf("match: got (%q, %v), want (tgw-2, true)", got.GetId(), ok)
	}
	if _, ok := findOrgTGWByShare(list, "share-9"); ok {
		t.Error("no match: want ok=false")
	}
	if _, ok := findOrgTGWByShare(nil, "share-1"); ok {
		t.Error("empty list: want ok=false")
	}
}

func TestTGWShareConflictHint(t *testing.T) {
	tgw := tgwTestOrgEntry("tgw-0abc", "tf-qa-tgw", "share-1")
	tgw.SetAttachments([]private_space.TransitGateway{
		tgwTestAttachment("available", "ps-a"),
		tgwTestAttachment("detached", "ps-ghost"),
		tgwTestAttachment("refreshing", "ps-b"),
	})
	want := `Transit gateway tgw-0abc ("tf-qa-tgw") already uses this resource share and is attached to ps-a, ps-b. ` +
		`To attach it to private space ps-c, set transit_gateway_id = "tgw-0abc" (for example a reference to the other resource's transit_gateway_id) ` +
		`and remove name, resource_share_id and resource_share_account.`
	if got := tgwShareConflictHint(tgw, "ps-c"); got != want {
		t.Errorf("hint mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestTGWOrgLock(t *testing.T) {
	ctx := context.Background()

	t.Run("second acquire blocks until unlock", func(t *testing.T) {
		l1, err := acquireTGWOrgLock(ctx, "org-block")
		if err != nil {
			t.Fatal(err)
		}
		got := make(chan error, 1)
		go func() {
			l2, err := acquireTGWOrgLock(ctx, "org-block")
			if err == nil {
				l2.Unlock()
			}
			got <- err
		}()
		select {
		case <-got:
			t.Fatal("second acquire returned while the lock was held")
		case <-time.After(100 * time.Millisecond):
		}
		l1.Unlock()
		select {
		case err := <-got:
			if err != nil {
				t.Fatalf("second acquire: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("second acquire did not proceed after Unlock")
		}
	})

	t.Run("cancelled ctx returns promptly", func(t *testing.T) {
		l1, err := acquireTGWOrgLock(ctx, "org-cancel")
		if err != nil {
			t.Fatal(err)
		}
		defer l1.Unlock()
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		start := time.Now()
		if _, err := acquireTGWOrgLock(cctx, "org-cancel"); err != context.Canceled {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Errorf("took %v, want < 100ms", d)
		}
	})

	t.Run("ctx cancelled while waiting", func(t *testing.T) {
		l1, err := acquireTGWOrgLock(ctx, "org-wait")
		if err != nil {
			t.Fatal(err)
		}
		defer l1.Unlock()
		cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if _, err := acquireTGWOrgLock(cctx, "org-wait"); err != context.DeadlineExceeded {
			t.Errorf("err = %v, want context.DeadlineExceeded", err)
		}
	})

	t.Run("claim round trip without holding the lock", func(t *testing.T) {
		l, err := acquireTGWOrgLock(ctx, "org-claim")
		if err != nil {
			t.Fatal(err)
		}
		if l.Claimed("share") {
			t.Fatal("share claimed before Claim")
		}
		l.Claim("share")
		if !l.Claimed("share") {
			t.Fatal("share not claimed after Claim")
		}
		l.Unlock()
		other := tgwOrgLockFor("org-claim")
		if !other.Claimed("share") {
			t.Fatal("claim lost after Unlock")
		}
		other.Release("share")
		if other.Claimed("share") {
			t.Fatal("share still claimed after Release")
		}
	})

	t.Run("orgs are independent", func(t *testing.T) {
		l1, err := acquireTGWOrgLock(ctx, "org-x")
		if err != nil {
			t.Fatal(err)
		}
		defer l1.Unlock()
		cctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		l2, err := acquireTGWOrgLock(cctx, "org-y")
		if err != nil {
			t.Fatalf("other org blocked: %v", err)
		}
		l2.Unlock()
	})
}
