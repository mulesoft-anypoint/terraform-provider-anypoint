package anypoint

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsRetryableMQStatus(t *testing.T) {
	for _, s := range []int{429, 500, 502, 503, 504} {
		if !isRetryableMQStatus(s) {
			t.Errorf("status %d should be retryable", s)
		}
	}
	for _, s := range []int{200, 201, 400, 401, 403, 404, 409} {
		if isRetryableMQStatus(s) {
			t.Errorf("status %d must not be retryable", s)
		}
	}
}

func TestRetryPolicyBounds(t *testing.T) {
	sum := func(p retryPolicy) (time.Duration, time.Duration) {
		var lo, hi time.Duration
		for i := 0; i < p.maxAttempts-1; i++ {
			mn, mx := p.backoff(i)
			lo += mn
			hi += mx
		}
		return lo, hi
	}

	if mqRetryPolicy.maxAttempts != 8 || mqRetryPolicy.base != 500*time.Millisecond || mqRetryPolicy.cap != 8*time.Second {
		t.Fatalf("unexpected MQ policy: %+v", mqRetryPolicy)
	}
	lo, hi := sum(mqRetryPolicy)
	if lo != 31500*time.Millisecond {
		t.Errorf("MQ min total sleep = %s, want 31.5s", lo)
	}
	// 50%% jitter is drawn from [0, backoff/2), so the ceiling is 47.25s (exclusive).
	if hi != 47250*time.Millisecond {
		t.Errorf("MQ max total sleep = %s, want 47.25s", hi)
	}

	// individual steps double, then clamp at the cap
	want := []time.Duration{500, 1000, 2000, 4000, 8000, 8000, 8000}
	for i, w := range want {
		mn, mx := mqRetryPolicy.backoff(i)
		if mn != w*time.Millisecond || mx != mn+mn/2 {
			t.Errorf("backoff(%d) = %s..%s, want %s..", i, mn, mx, w*time.Millisecond)
		}
	}

	// the read policy shares the MQ budget
	if mqReadRetryPolicy.maxAttempts != mqRetryPolicy.maxAttempts ||
		mqReadRetryPolicy.base != mqRetryPolicy.base || mqReadRetryPolicy.cap != mqRetryPolicy.cap {
		t.Errorf("read policy budget differs: %+v", mqReadRetryPolicy)
	}
	if !mqReadRetryPolicy.retryable(429) || mqReadRetryPolicy.retryable(503) || mqReadRetryPolicy.retryable(500) {
		t.Error("read policy must retry 429 only")
	}

	// BG policy is the historical one
	if bgRetryPolicy.maxAttempts != 5 || bgRetryPolicy.base != 250*time.Millisecond || bgRetryPolicy.cap != 4*time.Second {
		t.Fatalf("unexpected BG policy: %+v", bgRetryPolicy)
	}
	lo, hi = sum(bgRetryPolicy)
	if lo != 3750*time.Millisecond || hi != 5625*time.Millisecond {
		t.Errorf("BG total sleep = %s..%s, want 3.75s..5.625s", lo, hi)
	}
}

func fastPolicy(p retryPolicy) retryPolicy {
	p.base = time.Millisecond
	p.cap = 2 * time.Millisecond
	return p
}

func TestRetryTransient_BGUnchanged(t *testing.T) {
	// retryTransient sleeps with the real BG backoff, so drive the generic
	// function with the BG predicate and a fast base for the attempt count,
	// and check the BG predicate separately.
	var calls int32
	fn := func() (string, *http.Response, error) {
		atomic.AddInt32(&calls, 1)
		return "", &http.Response{StatusCode: http.StatusConflict}, context.DeadlineExceeded
	}
	_, httpr, err := retryTransientWith(context.Background(), "bg", fastPolicy(bgRetryPolicy), fn)
	if err == nil || httpr == nil || httpr.StatusCode != 409 {
		t.Fatalf("expected the last 409 to surface, got %v %v", httpr, err)
	}
	if calls != 5 {
		t.Errorf("409 retried %d times, want 5 attempts", calls)
	}
	for _, s := range []int{409, 429, 500, 503} {
		if !bgRetryPolicy.retryable(s) {
			t.Errorf("BG must retry %d", s)
		}
	}
	for _, s := range []int{400, 403, 404} {
		if bgRetryPolicy.retryable(s) {
			t.Errorf("BG must not retry %d", s)
		}
	}
}

func TestRetryTransient_Success(t *testing.T) {
	var calls int32
	res, httpr, err := retryTransient(context.Background(), "bg", func() (string, *http.Response, error) {
		atomic.AddInt32(&calls, 1)
		return "ok", &http.Response{StatusCode: 200}, nil
	})
	if err != nil || res != "ok" || httpr.StatusCode != 200 || calls != 1 {
		t.Fatalf("got %q %v %v calls=%d", res, httpr, err, calls)
	}
}

func TestRetryTransientWith_CtxCancelStopsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := mqRetryPolicy // real 500ms base
	var calls int32
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	_, _, err := retryTransientWith(ctx, "mq", p, func() (string, *http.Response, error) {
		atomic.AddInt32(&calls, 1)
		return "", &http.Response{StatusCode: 503}, context.DeadlineExceeded
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > 400*time.Millisecond || calls != 1 {
		t.Errorf("did not stop promptly: %s, calls=%d", time.Since(start), calls)
	}
}

func TestRetryMQDelete_404Semantics(t *testing.T) {
	prev := mqRetryPolicy
	mqRetryPolicy = fastPolicy(prev)
	defer func() { mqRetryPolicy = prev }()

	// 503 then 404: the first attempt deleted it
	var n int32
	httpr, err := retryMQDelete(context.Background(), "d", func() (*http.Response, error) {
		if atomic.AddInt32(&n, 1) == 1 {
			return &http.Response{StatusCode: 503}, context.DeadlineExceeded
		}
		return &http.Response{StatusCode: 404}, context.DeadlineExceeded
	})
	if err != nil || httpr == nil || httpr.StatusCode != 404 {
		t.Fatalf("503->404 must succeed, got %v %v", httpr, err)
	}

	// 404 on the very first attempt: genuine error
	n = 0
	httpr, err = retryMQDelete(context.Background(), "d", func() (*http.Response, error) {
		atomic.AddInt32(&n, 1)
		return &http.Response{StatusCode: 404}, context.DeadlineExceeded
	})
	if err == nil || n != 1 {
		t.Fatalf("first-attempt 404 must error after 1 call, got err=%v n=%d", err, n)
	}
}
