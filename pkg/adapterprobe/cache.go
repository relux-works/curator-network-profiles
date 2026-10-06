// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"runtime"
	"time"
)

type Mode string

const (
	Optimistic         Mode = ""
	Strict             Mode = "strict"
	Pinned             Mode = "pinned"
	DefaultNegativeTTL      = time.Minute
)

// AllowedBuild must come from independent qualification of the exact artifact,
// platform, applied adapter, recipe revision and scope. Version labels alone
// cannot produce these entries. No automatic migration of old approvals occurs.
type AllowedBuild struct {
	Adapter  Identity
	BuildID  string
	Recipe   string
	Platform string
	Scope    string
}

type Policy struct {
	Mode        Mode
	Allowlist   []AllowedBuild
	PinnedBuild string
	NegativeTTL time.Duration
	// SensitiveEgress carries the selected profile's sensitive_egress
	// declaration. Evaluate upgrades the effective mode to strict for
	// such profiles; Lookup and Verified enforce the same upgrade and
	// must not be used for admission (see Evaluate).
	SensitiveEgress bool
	// KnownBad is the operator known-bad set (from LoadKnownBad or
	// ParseKnownBad). Evaluate and Lookup always union it with the
	// embedded list; nil means no operator list.
	KnownBad *KnownBad
	// KnownBadErr fails evaluation closed: set it to the LoadKnownBad
	// failure when the configured or present operator known-bad list
	// could not be loaded. Evaluate and Lookup refuse without
	// consulting any other input.
	KnownBadErr error
}

const cacheCapacity = 128
const containmentVersion = "isolated-supervisor-v1"

type cacheEntry struct {
	Result      Result        `json:"result"`
	CheckedAt   time.Time     `json:"checked_at"`
	Platform    string        `json:"platform"`
	Containment string        `json:"containment"`
	Budget      time.Duration `json:"budget"`
	MAC         []byte        `json:"-"`
}

// Cache is bounded, process-local evidence. It never reads or writes a file.
// The secret is a fresh synthetic cache key, not an operator token. There is no
// public insertion/deserialization API: only a future trusted supervisor may
// issue conformance evidence. The current implementation issues none.
// HMAC detects corruption; metadata and result semantics are checked separately.
// Instances do not share locks. A zero Cache refuses instead of blocking.
type Cache struct {
	gate    chan struct{}
	secret  [32]byte
	entries map[string]cacheEntry
	// acquireHook, when non-nil, runs synchronously as the cache gate
	// acquisition is attempted. Tests set it to observe a goroutine
	// reaching the acquisition boundary; production leaves it nil.
	acquireHook func()
}

func NewCache(secret [32]byte) (*Cache, error) {
	if secret == ([32]byte{}) {
		return nil, &Unsupported{Reason: "cache_secret_required"}
	}
	return &Cache{gate: make(chan struct{}, 1), secret: secret, entries: make(map[string]cacheEntry)}, nil
}

// The primary key is exactly the binary SHA-256. Tuple/recipe/platform are
// evidence constraints, never additional components of the artifact key.
func cacheKey(_ Request, res Result) string { return res.BinarySHA256 }

func (c *Cache) lock(ctx context.Context) error {
	if c == nil || c.gate == nil {
		return &Unsupported{Reason: "invalid_cache"}
	}
	if hook := c.acquireHook; hook != nil {
		hook()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-c.gate
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Cache) unlock() { <-c.gate }
func (c *Cache) seal(entry cacheEntry) []byte {
	data, _ := json.Marshal(entry)
	mac := hmac.New(sha256.New, c.secret[:])
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func validEvidence(r Result) bool {
	build, err := BuildID(r.BinarySHA256)
	if err != nil || build != r.BuildID || r.Adapter.Adapter != "generic-env-v1" || !identityRE.MatchString(r.Adapter.Harness) || !identityRE.MatchString(r.Adapter.Entrypoint) || !recipeRE.MatchString(r.Recipe) || r.Scope != TransportScope || len(r.Observed) > 16 {
		return false
	}
	if r.Verified {
		if r.Reason != "proxy_attempt_observed" || len(r.Observed) == 0 {
			return false
		}
	} else if r.Reason != "operation_no_proxy_attempt" || len(r.Observed) != 0 {
		// Early exit, authentication, cancellation, deadline, setup, calibration,
		// start and cleanup errors are inconclusive and never negative evidence.
		return false
	}
	recipe, ok := recipes[r.Recipe]
	if !ok || recipe.Unavailable != "" || recipe.Harness != r.Adapter.Harness || recipe.Entrypoint != r.Adapter.Entrypoint {
		return false
	}
	for _, o := range r.Observed {
		if o != recipe.Expected || authority(o.Target, "") != o.Target {
			return false
		}
	}
	return true
}

func effectiveBudget(req Request) time.Duration {
	if req.Timeout == 0 {
		return DefaultTimeout
	}
	return req.Timeout
}
func negativeTTL(policy Policy) time.Duration {
	if policy.NegativeTTL == 0 {
		return DefaultNegativeTTL
	}
	return policy.NegativeTTL
}

func (c *Cache) lookup(ctx context.Context, req Request, res Result, policy Policy) (Result, bool, error) {
	if err := c.lock(ctx); err != nil {
		return res, false, err
	}
	defer c.unlock()
	entry, ok := c.entries[cacheKey(req, res)]
	if !ok {
		return res, false, nil
	}
	if !hmac.Equal(entry.MAC, c.seal(entry)) || !validEvidence(entry.Result) {
		return res, false, &Unsupported{Reason: "cache_integrity_failed"}
	}
	age := time.Since(entry.CheckedAt)
	if age < 0 || entry.Result.Adapter != req.Adapter || entry.Result.Recipe != req.Recipe || entry.Result.Scope != res.Scope || entry.Platform != runtime.GOOS || entry.Containment != containmentVersion || entry.Result.BuildID != res.BuildID {
		return res, false, nil
	}
	if !entry.Result.Verified && (age >= negativeTTL(policy) || entry.Budget != effectiveBudget(req)) {
		return res, false, nil
	}
	if err := ctx.Err(); err != nil {
		return res, false, err
	}
	result := entry.Result
	result.Observed = append([]Observation(nil), result.Observed...)
	return result, true, nil
}

// record is deliberately private and is not called by Probe while supervision
// is unavailable. Its result must follow completed, checked process termination
// and cleanup. External caller-supplied results cannot populate the cache.
func (c *Cache) record(ctx context.Context, req Request, res Result, policy Policy, checked time.Time) error {
	if !validEvidence(res) {
		return &Unsupported{Reason: "invalid_evidence"}
	}
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	now := time.Now()
	if checked.After(now) || checked.IsZero() {
		return &Unsupported{Reason: "invalid_evidence"}
	}
	for key, entry := range c.entries {
		if !hmac.Equal(entry.MAC, c.seal(entry)) || !validEvidence(entry.Result) || !entry.Result.Verified && now.Sub(entry.CheckedAt) >= negativeTTL(policy) {
			delete(c.entries, key)
		}
	}
	key := cacheKey(req, res)
	if _, exists := c.entries[key]; !exists && len(c.entries) >= cacheCapacity {
		var oldest string
		var oldestTime time.Time
		for k, entry := range c.entries {
			if oldest == "" || entry.CheckedAt.Before(oldestTime) {
				oldest, oldestTime = k, entry.CheckedAt
			}
		}
		delete(c.entries, oldest)
	}
	res.Observed = append([]Observation(nil), res.Observed...)
	entry := cacheEntry{Result: res, CheckedAt: checked, Platform: runtime.GOOS, Containment: containmentVersion, Budget: effectiveBudget(req)}
	entry.MAC = c.seal(entry)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.entries[key] = entry
	return nil
}

// Lookup is a low-level, non-authorizing evidence inspection helper. It
// is not a launch verifier and must not be used for admission: use
// Evaluate for every consumer event (plans, direct profiles, dry runs,
// real launches and live reattach), including unqualified builds with
// their provenance. Lookup enforces the same known-bad, vendor, recipe,
// sensitivity and pin guards as Evaluate, but it never admits an
// unqualified build: missing evidence refuses with evidence_missing.
// Strict evaluates trusted exact approvals without consulting Cache.
func Lookup(ctx context.Context, req Request, policy Policy) (Result, error) {
	if policy.KnownBadErr != nil {
		return failed(Result{}, knownBadReason(policy.KnownBadErr))
	}
	if policy.NegativeTTL < 0 {
		return failed(Result{}, "invalid_policy")
	}
	switch policy.Mode {
	case Optimistic, Strict, Pinned:
	default:
		return failed(Result{}, "invalid_policy")
	}
	ctx, cancel := bounded(ctx, req)
	defer cancel()
	res, err := identify(ctx, req)
	if err != nil {
		return res, err
	}
	if EmbeddedKnownBad().Union(policy.KnownBad).Contains(res.BinarySHA256) {
		return failed(res, "known_bad_build")
	}
	if !KnownVendorLine(req.Adapter) {
		return failed(res, "vendor_line_unsupported")
	}
	recipe, ok := recipes[req.Recipe]
	if !ok || recipe.Harness != req.Adapter.Harness || recipe.Entrypoint != req.Adapter.Entrypoint {
		return failed(res, "recipe_unsupported")
	}
	if policy.Mode == Pinned && policy.PinnedBuild != res.BuildID {
		return failed(res, "pinned_miss")
	}
	// Sensitive profiles require an exact allowlist: optimistic and
	// pinned-sensitive never consult the process-local cache for a
	// positive. This mirrors Evaluate's strict upgrade.
	if EffectiveMode(policy) == Strict || (policy.Mode == Pinned && policy.SensitiveEgress) {
		for _, allowed := range policy.Allowlist {
			if ctx.Err() != nil {
				return interrupted(ctx, res)
			}
			if allowed.Adapter == req.Adapter && allowed.BuildID == res.BuildID && allowed.Recipe == req.Recipe && allowed.Platform == runtime.GOOS && allowed.Scope == TransportScope {
				res.Verified, res.Reason = true, "allowlisted"
				if ctx.Err() != nil {
					return interrupted(ctx, res)
				}
				return res, nil
			}
		}
		return failed(res, "strict_miss")
	}
	if req.Cache != nil {
		cached, ok, err := req.Cache.lookup(ctx, req, res, policy)
		if ctx.Err() != nil {
			return interrupted(ctx, res)
		}
		if err != nil {
			return failed(res, "cache_integrity_failed")
		}
		if ok {
			if !cached.Verified {
				return failed(cached, cached.Reason)
			}
			if ctx.Err() != nil {
				return interrupted(ctx, res)
			}
			return cached, nil
		}
	}
	if ctx.Err() != nil {
		return interrupted(ctx, res)
	}
	return failed(res, "evidence_missing")
}

// Verified is a low-level helper reserved for an explicitly authorized
// fresh proxy launch check on the destination host. It is not the
// option-C verifier: use Evaluate for admission, including unqualified
// builds. Legacy disk caches refuse without even opening the path:
// arbitrary filesystems cannot guarantee bounded I/O, ownership or authenticity.
// Strict is lookup-only. Optimistic/pinned misses require a supervisor and
// return Unsupported. Nothing creates runtime state or a child process.
func Verified(ctx context.Context, req Request, cachePath string, policy Policy) (Result, error) {
	ctx, cancel := bounded(ctx, req)
	defer cancel()
	res, err := Lookup(ctx, req, policy)
	if EffectiveMode(policy) == Strict || (policy.Mode == Pinned && policy.SensitiveEgress) || err != nil && res.Reason != "evidence_missing" {
		return res, err
	}
	// Policy, pin and request validation precede persistence requirements.
	if cachePath != "" {
		if ctx.Err() != nil {
			return interrupted(ctx, res)
		}
		return failed(res, "persistent_cache_unsupported")
	}
	// Prospective qualification checks host capability even on a cache hit.
	// Lookup may inspect historical evidence, but cannot enable this supervisor.
	return qualificationUnavailable(ctx, req, res, runtime.GOOS)
}
