// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testCache(t *testing.T) *Cache {
	t.Helper()
	var secret [32]byte
	secret[0] = 1
	c, err := NewCache(secret)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func conformance(t *testing.T, req Request, pass bool) Result {
	t.Helper()
	res, err := identify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	res.Verified = pass
	res.Reason = "operation_no_proxy_attempt"
	if pass {
		res.Reason = "proxy_attempt_observed"
		res.Observed = []Observation{recipes[req.Recipe].Expected}
	}
	return res
}
func store(t *testing.T, c *Cache, req Request, res Result, at time.Time) {
	t.Helper()
	if err := c.record(context.Background(), req, res, Policy{}, at); err != nil {
		t.Fatal(err)
	}
}

// snapshotCacheEntries deep-copies the full cache state: observations,
// timestamps, metadata and MACs. A replacement or alteration of an
// entry must fail comparison, not just a change in cardinality.
func snapshotCacheEntries(t *testing.T, c *Cache) map[string]cacheEntry {
	t.Helper()
	out := make(map[string]cacheEntry, len(c.entries))
	for key, entry := range c.entries {
		cp := entry
		cp.Result.Observed = append([]Observation(nil), entry.Result.Observed...)
		cp.MAC = append([]byte(nil), entry.MAC...)
		out[key] = cp
	}
	return out
}

func assertCacheEntriesUnchanged(t *testing.T, c *Cache, want map[string]cacheEntry) {
	t.Helper()
	if len(c.entries) != len(want) {
		t.Fatalf("cache holds %d entries; want %d", len(c.entries), len(want))
	}
	for key, w := range want {
		got, ok := c.entries[key]
		if !ok {
			t.Fatalf("cache entry %q missing after refusal", key)
		}
		if !reflect.DeepEqual(got, w) {
			t.Fatalf("cache entry %q changed: %+v vs %+v", key, got, w)
		}
	}
}

func TestDigestOnlyCacheAndScopedEvidence(t *testing.T) {
	c := testCache(t)
	req := request()
	req.Cache = c
	first := conformance(t, req, true)
	store(t, c, req, first, time.Now())
	res, err := Lookup(context.Background(), req, Policy{})
	if err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	if cacheKey(req, first) != first.BinarySHA256 || len(c.entries) != 1 {
		t.Fatal("cache key not binary digest")
	}
	// Returned evidence never aliases cache storage.
	res.Observed[0].Target = "corrupted"
	res, err = Lookup(context.Background(), req, Policy{})
	if err != nil || res.Observed[0].Target != "probe.invalid:80" {
		t.Fatal("mutable cached result")
	}
	for _, tc := range []struct {
		name   string
		change func(*Request)
		reason string
	}{
		{"valid recipe change misses its cache scope", func(r *Request) { r.Recipe = "fake-connect-v1" }, "evidence_missing"},
		{"unknown harness refuses before the cache", func(r *Request) { r.Adapter.Harness = "another-harness" }, "vendor_line_unsupported"},
		{"unregistered entrypoint refuses before the cache", func(r *Request) { r.Adapter.Entrypoint = "another-entrypoint" }, "recipe_unsupported"},
		{"different artifact misses its digest key", func(r *Request) { r.Artifact = append(append([]byte(nil), r.Artifact...), byte(1)) }, "evidence_missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := req
			tc.change(&other)
			res, err := Lookup(context.Background(), other, Policy{})
			assertFailure(t, res, err, tc.reason)
		})
	}
	// Cache-scope mismatches with valid registered tuples: the same
	// artifact bytes under a different known line miss on adapter and
	// recipe constraints, not on vendor guards.
	sameBytes := claudeRequest()
	sameBytes.Artifact = append([]byte(nil), req.Artifact...)
	sameBytes.Cache = c
	res, err = Lookup(context.Background(), sameBytes, Policy{})
	assertFailure(t, res, err, "evidence_missing")
	// A platform's boolean cannot certify another platform's containment.
	entry := c.entries[first.BinarySHA256]
	entry.Platform = "different-platform"
	entry.MAC = c.seal(entry)
	c.entries[first.BinarySHA256] = entry
	res, err = Lookup(context.Background(), req, Policy{})
	assertFailure(t, res, err, "evidence_missing")
	entry.Platform = runtime.GOOS
	entry.MAC = c.seal(entry)
	c.entries[first.BinarySHA256] = entry
	// Even intact cached transport evidence cannot enable unavailable supervision.
	res, err = Verified(context.Background(), req, "", Policy{})
	reason := "platform_unsupported"
	if runtime.GOOS == "darwin" {
		reason = "secure_supervisor_required"
	}
	if runtime.GOOS == "linux" {
		reason = "namespace_supervisor_required"
	}
	assertFailure(t, res, err, reason)
}

func TestCacheTamperAndSemanticValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*cacheEntry)
		reseal bool
	}{
		{"bit corruption", func(e *cacheEntry) { e.Result.Reason = "private-body-canary" }, false},
		{"forged positive without observation", func(e *cacheEntry) { e.Result.Observed = nil }, true},
		{"path in observation", func(e *cacheEntry) { e.Result.Observed[0].Target = "host:80/private-canary" }, true},
		{"arbitrary kind", func(e *cacheEntry) { e.Result.Observed[0].Kind = "private-body-canary" }, true},
		{"incidental startup", func(e *cacheEntry) { e.Result.Observed[0].Target = "telemetry.invalid:80" }, true},
		{"adapter forgery", func(e *cacheEntry) { e.Result.Adapter.Adapter = "muse-env-v1" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testCache(t)
			req := request()
			req.Cache = c
			good := conformance(t, req, true)
			store(t, c, req, good, time.Now())
			entry := c.entries[good.BinarySHA256]
			tc.mutate(&entry)
			if tc.reseal {
				entry.MAC = c.seal(entry)
			}
			c.entries[good.BinarySHA256] = entry
			res, err := Lookup(context.Background(), req, Policy{})
			assertFailure(t, res, err, "cache_integrity_failed")
			if len(res.Observed) != 0 {
				t.Fatal("returned tainted evidence")
			}
		})
	}
}

func TestNegativeSemanticsAndEviction(t *testing.T) {
	c := testCache(t)
	req := request()
	req.Cache = c
	negative := conformance(t, req, false)
	store(t, c, req, negative, time.Now())
	res, err := Lookup(context.Background(), req, Policy{})
	assertFailure(t, res, err, "operation_no_proxy_attempt")
	other := req
	other.Timeout = time.Second
	res, err = Lookup(context.Background(), other, Policy{})
	assertFailure(t, res, err, "evidence_missing")
	store(t, c, req, negative, time.Now().Add(-2*DefaultNegativeTTL))
	res, err = Lookup(context.Background(), req, Policy{})
	assertFailure(t, res, err, "evidence_missing")
	for _, reason := range []string{"cancelled", "deadline_exceeded", "timeout", "exited_without_proxy_attempt", "start_failed", "isolation_failed", "sandbox_calibration_failed", "cleanup_failed", "credential_free_recipe_unavailable"} {
		invalid := negative
		invalid.Reason = reason
		if err := c.record(context.Background(), req, invalid, Policy{}, time.Now()); err == nil {
			t.Fatalf("cached %s as binary verdict", reason)
		}
	}
	for i := 0; i < cacheCapacity+20; i++ {
		candidate := request()
		candidate.Artifact = append(candidate.Artifact, []byte(fmt.Sprint(i))...)
		store(t, c, candidate, conformance(t, candidate, true), time.Now())
	}
	if len(c.entries) > cacheCapacity {
		t.Fatal("unbounded cache growth")
	}
	if _, ok := c.entries[negative.BinarySHA256]; ok {
		t.Fatal("expired negative retained")
	}
	final := conformance(t, req, true)
	store(t, c, req, final, time.Now())
	res, err = Lookup(context.Background(), req, Policy{})
	if err != nil || !res.Verified {
		t.Fatal("capacity permanently blocked fresh evidence")
	}
}

func TestCacheContentionCancellation(t *testing.T) {
	c := testCache(t)
	req := request()
	req.Cache = c
	good := conformance(t, req, true)
	store(t, c, req, good, time.Now())
	before := snapshotCacheEntries(t, c)
	c.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	c.acquireHook = func() { close(entered) }
	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() { res, err := Lookup(ctx, req, Policy{}); done <- outcome{res, err} }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("lookup never reached the cache gate")
	}
	c.acquireHook = nil
	cancel()
	select {
	case out := <-done:
		assertFailure(t, out.res, out.err, "cancelled")
	case <-time.After(5 * time.Second):
		t.Fatal("cache wait outlived cancellation")
	}
	<-c.gate
	assertCacheEntriesUnchanged(t, c, before)
	expired, cancelDeadline := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelDeadline()
	<-expired.Done()
	if err := c.record(expired, req, good, Policy{}, time.Now()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline cached a verdict")
	}
}

// A live Lookup that reaches the held cache gate and whose deadline
// then expires must refuse with a timely typed deadline_exceeded,
// before the gate is released. Entry is established through the
// acquisition hook reporting a live context; expiration is established
// after that acknowledgement; no scheduling sleep orders the test.
func TestCacheGateDeadlineLookup(t *testing.T) {
	c := testCache(t)
	req := request()
	req.Cache = c
	store(t, c, req, conformance(t, req, true), time.Now())
	before := snapshotCacheEntries(t, c)
	c.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	entered := make(chan error, 1)
	c.acquireHook = func() { entered <- ctx.Err() }
	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() { res, err := Lookup(ctx, req, Policy{}); done <- outcome{res, err} }()
	select {
	case hookErr := <-entered:
		if hookErr != nil {
			t.Fatalf("acquisition entered with expired context: %v", hookErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lookup never reached the cache gate")
	}
	c.acquireHook = nil
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("deadline never expired after live entry")
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("context error=%v; want context.DeadlineExceeded", ctx.Err())
	}
	select {
	case out := <-done:
		assertFailure(t, out.res, out.err, "deadline_exceeded")
	case <-time.After(5 * time.Second):
		t.Fatal("lookup outlived its expired deadline")
	}
	<-c.gate
	assertCacheEntriesUnchanged(t, c, before)
}

func TestPoliciesAndContentPin(t *testing.T) {
	req := request()
	strict, identity := approved(t, req)
	for _, tc := range []struct {
		policy Policy
		reason string
		pass   bool
	}{
		{strict, "allowlisted", true},
		{Policy{Mode: Strict}, "strict_miss", false},
		{Policy{Mode: Pinned, PinnedBuild: identity.BuildID}, "evidence_missing", false},
		{Policy{Mode: Pinned, PinnedBuild: "old-label"}, "pinned_miss", false},
		{Policy{Mode: Pinned}, "pinned_miss", false},
		{Policy{Mode: "unknown"}, "invalid_policy", false},
		{Policy{NegativeTTL: -1}, "invalid_policy", false},
	} {
		res, err := Lookup(context.Background(), req, tc.policy)
		if tc.pass {
			if err != nil || !res.Verified || res.Reason != tc.reason {
				t.Fatalf("%+v %v", res, err)
			}
		} else {
			assertFailure(t, res, err, tc.reason)
		}
	}
	changed := req
	changed.Artifact = append(append([]byte(nil), req.Artifact...), byte(1))
	res, err := Lookup(context.Background(), changed, Policy{Mode: Pinned, PinnedBuild: identity.BuildID})
	assertFailure(t, res, err, "pinned_miss")
	for _, mutate := range []func(*AllowedBuild){func(a *AllowedBuild) { a.Recipe = "fake-http-v2" }, func(a *AllowedBuild) { a.Platform = "other" }, func(a *AllowedBuild) { a.Scope = "all-child-transports" }, func(a *AllowedBuild) { a.BuildID = strings.Replace(a.BuildID, "sha256-", "sha256:", 1) }} {
		clone := strict
		clone.Allowlist = append([]AllowedBuild(nil), strict.Allowlist...)
		mutate(&clone.Allowlist[0])
		res, err := Lookup(context.Background(), req, clone)
		assertFailure(t, res, err, "strict_miss")
	}
}

func TestUntrustedDiskCachesNeverOpened(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(path, []byte(`{"verified":true,"reason":"private-canary"}`), 0666); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, link, dir, filepath.Join(dir, "missing", "cache")} {
		res, err := Verified(context.Background(), request(), candidate, Policy{})
		assertFailure(t, res, err, "persistent_cache_unsupported")
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "private-canary") {
		t.Fatal("verifier changed cache")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("verifier created state")
	}
}

func TestPinMissPrecedesPersistentCache(t *testing.T) {
	res, err := Verified(context.Background(), request(), "/never-open", Policy{Mode: Pinned, PinnedBuild: "old-version"})
	assertFailure(t, res, err, "pinned_miss")
}
