package anypoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	ame "github.com/mulesoft-anypoint/anypoint-client-go/ame"
	ame_binding "github.com/mulesoft-anypoint/anypoint-client-go/ame_binding"
	amq "github.com/mulesoft-anypoint/anypoint-client-go/amq"
)

// mqMock serves the MQ admin paths. script maps "<METHOD> <kind>" (kind is
// queue, exchange, binding or rule) to the statuses to return in order; once
// exhausted, the default success status for the method is returned.
type mqMock struct {
	mu     sync.Mutex
	script map[string][]int
	calls  map[string]int
}

func newMQMock(script map[string][]int) *mqMock {
	return &mqMock{script: script, calls: map[string]int{}}
}

func mqKind(path string) string {
	switch {
	case strings.Contains(path, "/rules/routing"):
		return "rule"
	case strings.Contains(path, "/bindings/"):
		return "binding"
	case strings.Contains(path, "/destinations/queues/"):
		return "queue"
	case strings.Contains(path, "/destinations/exchanges/"):
		return "exchange"
	}
	return "unknown"
}

func (m *mqMock) count(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[key]
}

func (m *mqMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	kind := mqKind(r.URL.Path)
	key := r.Method + " " + kind
	m.mu.Lock()
	m.calls[key]++
	status := 0
	if s := m.script[key]; len(s) > 0 {
		status = s[0]
		m.script[key] = s[1:]
	}
	m.mu.Unlock()
	if status == 0 {
		switch r.Method {
		case http.MethodPut:
			status = http.StatusCreated
		case http.MethodDelete:
			status = http.StatusNoContent
		default:
			status = http.StatusOK
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status >= 400 {
		_, _ = w.Write([]byte(`{"status":"failure","statusMessage":"scripted"}`))
		return
	}
	if r.Method == http.MethodDelete {
		return
	}
	switch kind {
	case "queue":
		_, _ = w.Write([]byte(`{"queueId":"q1","type":"queue","defaultTtl":604800000,"defaultLockTtl":120000,"defaultDeliveryDelay":0,"encrypted":false,"fifo":false}`))
	case "exchange":
		_, _ = w.Write([]byte(`{"exchangeId":"x1","type":"exchange","encrypted":false}`))
	case "binding":
		_, _ = w.Write([]byte(`{"exchangeId":"x1","queueId":"q1","routingRules":[{"propertyName":"k","propertyType":"STRING","matcherType":"EQ","value":"v"}]}`))
	default:
		_, _ = w.Write([]byte(`{}`))
	}
}

func mqTestMeta(t *testing.T, script map[string][]int) (ProviderConfOutput, *mqMock) {
	t.Helper()
	prevMQ, prevRead := mqRetryPolicy, mqReadRetryPolicy
	mqRetryPolicy.base, mqRetryPolicy.cap = time.Millisecond, 2*time.Millisecond
	mqReadRetryPolicy.base, mqReadRetryPolicy.cap = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { mqRetryPolicy, mqReadRetryPolicy = prevMQ, prevRead })

	mock := newMQMock(script)
	ts := httptest.NewServer(mock)
	t.Cleanup(ts.Close)

	amqCfg := amq.NewConfiguration()
	amqCfg.Servers = amq.ServerConfigurations{{URL: ts.URL}}
	ameCfg := ame.NewConfiguration()
	ameCfg.Servers = ame.ServerConfigurations{{URL: ts.URL}}
	bindCfg := ame_binding.NewConfiguration()
	bindCfg.Servers = ame_binding.ServerConfigurations{{URL: ts.URL}}
	return ProviderConfOutput{
		access_token:     "x",
		server_index:     0,
		amqclient:        amq.NewAPIClient(amqCfg),
		ameclient:        ame.NewAPIClient(ameCfg),
		amebindingclient: ame_binding.NewAPIClient(bindCfg),
	}, mock
}

func amqTestData(t *testing.T) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, resourceAMQ().Schema, map[string]any{
		"org_id": "o1", "env_id": "e1", "region_id": "us-east-2", "queue_id": "q1",
	})
}

func ameTestData(t *testing.T) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, resourceAME().Schema, map[string]any{
		"org_id": "o1", "env_id": "e1", "region_id": "us-east-2", "exchange_id": "x1",
	})
}

func bindingTestData(t *testing.T) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, resourceAMEBinding().Schema, map[string]any{
		"org_id": "o1", "env_id": "e1", "region_id": "us-east-2", "exchange_id": "x1", "queue_id": "q1",
		"rule_str_compare": []any{map[string]any{
			"property_name": "k", "property_type": "STRING", "matcher_type": "EQ", "value": "v",
		}},
	})
}

func TestAMQCreate_429_503_200(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"PUT queue": {429, 503}})
	d := amqTestData(t)
	if diags := resourceAMQCreate(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if n := mock.count("PUT queue"); n != 3 {
		t.Errorf("PUT attempts = %d, want 3", n)
	}
	if d.Id() == "" {
		t.Error("id not set")
	}
}

func TestAMQCreate_403_NoRetry(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"PUT queue": {403, 403, 403}})
	diags := resourceAMQCreate(context.Background(), amqTestData(t), meta)
	if !diags.HasError() {
		t.Fatal("expected error")
	}
	if n := mock.count("PUT queue"); n != 1 {
		t.Errorf("PUT attempts = %d, want 1", n)
	}
}

func TestAMQCreate_409_NoRetry(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"PUT queue": {409, 409}})
	diags := resourceAMQCreate(context.Background(), amqTestData(t), meta)
	if !diags.HasError() {
		t.Fatal("expected error")
	}
	if n := mock.count("PUT queue"); n != 1 {
		t.Errorf("PUT attempts = %d, want 1", n)
	}
	if !strings.Contains(diags[0].Detail, "scripted") {
		t.Errorf("detail lost the API body: %q", diags[0].Detail)
	}
}

func TestAMQCreate_GivesUpAfterBudget(t *testing.T) {
	always := make([]int, 20)
	for i := range always {
		always[i] = 503
	}
	meta, mock := mqTestMeta(t, map[string][]int{"PUT queue": always})
	diags := resourceAMQCreate(context.Background(), amqTestData(t), meta)
	if !diags.HasError() {
		t.Fatal("expected error")
	}
	if n := mock.count("PUT queue"); n != 8 {
		t.Errorf("PUT attempts = %d, want 8", n)
	}
}

func TestAMQDelete_503Then404_Success(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"DELETE queue": {503, 404}})
	d := amqTestData(t)
	d.SetId("o1/e1/us-east-2/q1")
	if diags := resourceAMQDelete(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if n := mock.count("DELETE queue"); n != 2 {
		t.Errorf("DELETE attempts = %d, want 2", n)
	}
	if d.Id() != "" {
		t.Error("id should be cleared")
	}
}

func TestAMQDelete_404FirstAttempt_Error(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"DELETE queue": {404}})
	d := amqTestData(t)
	d.SetId("o1/e1/us-east-2/q1")
	if diags := resourceAMQDelete(context.Background(), d, meta); !diags.HasError() {
		t.Fatal("expected error on first-attempt 404")
	}
	if n := mock.count("DELETE queue"); n != 1 {
		t.Errorf("DELETE attempts = %d, want 1", n)
	}
}

func TestAMQCreate_PostCreateRead503ThenOK_NoTaint(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"GET queue": {503}})
	d := amqTestData(t)
	if diags := resourceAMQCreate(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("create must not fail on a transient post-create read: %v", diags)
	}
	if n := mock.count("GET queue"); n != 2 {
		t.Errorf("GET attempts = %d, want 2", n)
	}
	if d.Id() == "" {
		t.Error("id must be kept")
	}
}

func TestAMQRead_429Then200(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"GET queue": {429}})
	d := amqTestData(t)
	d.SetId("o1/e1/us-east-2/q1")
	if diags := resourceAMQRead(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("read failed: %v", diags)
	}
	if n := mock.count("GET queue"); n != 2 {
		t.Errorf("GET attempts = %d, want 2", n)
	}
}

func TestAMQRead_503_NoRetry(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"GET queue": {503}})
	d := amqTestData(t)
	d.SetId("o1/e1/us-east-2/q1")
	if diags := resourceAMQRead(context.Background(), d, meta); !diags.HasError() {
		t.Fatal("expected error")
	}
	if n := mock.count("GET queue"); n != 1 {
		t.Errorf("GET attempts = %d, want 1", n)
	}
}

func TestAMQRead_404_ClearsID(t *testing.T) {
	meta, _ := mqTestMeta(t, map[string][]int{"GET queue": {404}})
	d := amqTestData(t)
	d.SetId("o1/e1/us-east-2/q1")
	if diags := resourceAMQRead(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("404 read must not error: %v", diags)
	}
	if d.Id() != "" {
		t.Error("id should be cleared on 404")
	}
}

func TestAMECreateDelete_Retry(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{
		"PUT exchange":    {503, 429},
		"GET exchange":    {503},
		"DELETE exchange": {500, 404},
	})
	d := ameTestData(t)
	if diags := resourceAMECreate(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if n := mock.count("PUT exchange"); n != 3 {
		t.Errorf("PUT attempts = %d, want 3", n)
	}
	if n := mock.count("GET exchange"); n != 2 {
		t.Errorf("post-create GET attempts = %d, want 2", n)
	}
	if diags := resourceAMEDelete(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if n := mock.count("DELETE exchange"); n != 2 {
		t.Errorf("DELETE attempts = %d, want 2", n)
	}
}

func TestAME_403_NoRetry(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"PUT exchange": {403}})
	if diags := resourceAMECreate(context.Background(), ameTestData(t), meta); !diags.HasError() {
		t.Fatal("expected error")
	}
	if n := mock.count("PUT exchange"); n != 1 {
		t.Errorf("PUT attempts = %d, want 1", n)
	}
}

func TestAMEBindingCreateDelete_Retry(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{
		"PUT binding":    {503},
		"PUT rule":       {429, 502},
		"GET binding":    {429},
		"DELETE binding": {503, 404},
	})
	d := bindingTestData(t)
	if diags := resourceAMEBindingCreate(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("create failed: %v", diags)
	}
	if n := mock.count("PUT binding"); n != 2 {
		t.Errorf("binding PUT attempts = %d, want 2", n)
	}
	if n := mock.count("PUT rule"); n != 3 {
		t.Errorf("rule PUT attempts = %d, want 3", n)
	}
	if n := mock.count("GET binding"); n != 2 {
		t.Errorf("post-create GET attempts = %d, want 2", n)
	}
	if diags := resourceAMEBindingDelete(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("delete failed: %v", diags)
	}
	if n := mock.count("DELETE binding"); n != 2 {
		t.Errorf("DELETE attempts = %d, want 2", n)
	}
}

func TestAMEBindingRulesDelete_Retry(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"DELETE rule": {503, 404}})
	d := bindingTestData(t)
	d.SetId("o1/e1/us-east-2/x1/q1")
	if diags := resourceAMEBindingRulesDelete(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("rule delete failed: %v", diags)
	}
	if n := mock.count("DELETE rule"); n != 2 {
		t.Errorf("DELETE attempts = %d, want 2", n)
	}
}

func TestAMEBinding_409_NoRetry(t *testing.T) {
	meta, mock := mqTestMeta(t, map[string][]int{"PUT binding": {409}})
	if diags := resourceAMEBindingCreate(context.Background(), bindingTestData(t), meta); !diags.HasError() {
		t.Fatal("expected error")
	}
	if n := mock.count("PUT binding"); n != 1 {
		t.Errorf("PUT attempts = %d, want 1", n)
	}
}
