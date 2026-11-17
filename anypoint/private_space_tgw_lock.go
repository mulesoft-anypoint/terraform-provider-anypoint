package anypoint

import (
	"context"
	"sync"
)

// tgwOrgLocks holds one *tgwOrgLock per organization. Package-level mutable
// state is an exception to the AGENTS.md rule: it only serialises the
// transit gateway Create flows of one org inside this provider process
// (precedent: policyTemplateCache in policy_template_cache.go).
var tgwOrgLocks sync.Map // org -> *tgwOrgLock

// tgwOrgLock serialises transit gateway creates for one organization and
// remembers which resource shares this process has already claimed.
type tgwOrgLock struct {
	ch chan struct{} // capacity 1; a token in the channel means "held"

	mu     sync.Mutex // guards claims
	claims map[string]struct{}
}

// tgwOrgLockFor returns the lock entry of org without acquiring it, so that
// callers such as Delete can drop a claim without taking the lock.
func tgwOrgLockFor(org string) *tgwOrgLock {
	if v, ok := tgwOrgLocks.Load(org); ok {
		return v.(*tgwOrgLock)
	}
	v, _ := tgwOrgLocks.LoadOrStore(org, &tgwOrgLock{
		ch:     make(chan struct{}, 1),
		claims: map[string]struct{}{},
	})
	return v.(*tgwOrgLock)
}

// acquireTGWOrgLock blocks until the org lock is held or ctx is done, in
// which case it returns ctx.Err().
func acquireTGWOrgLock(ctx context.Context, org string) (*tgwOrgLock, error) {
	l := tgwOrgLockFor(org)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case l.ch <- struct{}{}:
		return l, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Unlock releases the org lock.
func (l *tgwOrgLock) Unlock() {
	<-l.ch
}

// Claimed reports whether share was claimed by this process.
func (l *tgwOrgLock) Claimed(share string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.claims[share]
	return ok
}

// Claim records that a resource in this process owns share.
func (l *tgwOrgLock) Claim(share string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.claims[share] = struct{}{}
}

// Release drops the claim on share. It does not require holding the org lock.
func (l *tgwOrgLock) Release(share string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.claims, share)
}
