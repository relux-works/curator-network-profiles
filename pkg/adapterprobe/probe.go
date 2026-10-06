// SPDX-License-Identifier: Apache-2.0

// Package adapterprobe evaluates narrowly scoped adapter evidence without
// reading the operator's filesystem or starting a harness. Fresh qualification
// fails closed until a trusted platform supervisor is implemented. Evaluate
// applies the option-C launch policy (qualified, unqualified with typed
// provenance, or refused) over the same snapshot identity.
package adapterprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"runtime"
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

const DefaultTimeout = 10 * time.Second
const maxArtifactBytes = 256 << 20
const TransportScope = "generic-proxy-transport-v1"

var ErrUnsupported = errors.New("adapter probe unsupported")

// Unsupported supplies a fixed machine-readable reason and the shared refusal
// code. No raw operating-system diagnostic or caller path crosses this boundary.
type Unsupported struct{ Reason string }

func (e *Unsupported) Error() string        { return "adapter probe unsupported: " + e.Reason }
func (e *Unsupported) Is(target error) bool { return target == ErrUnsupported }
func (e *Unsupported) Unwrap() error {
	return refusal.New(refusal.CodeScopeUnsupported, "adapter", e.Reason)
}

type Identity struct {
	Adapter    string `json:"adapter"`
	Harness    string `json:"harness"`
	Entrypoint string `json:"entrypoint"`
}

// Request.Artifact is a caller-owned snapshot, immutable for the duration of
// the call. The package never opens Binary. A successful decision identifies
// ONLY this snapshot; the real process owner must execute exactly these bytes
// from its protected staging area. Scripts and mutable runtime closures are
// refused. Recipe is a revisioned capability ID, shared by all consumers of
// the tuple. Args must be empty (any entry refuses with
// unversioned_invocation). Binary and Sandbox are ignored legacy fields from
// an unpublished execution design: Binary is never opened and Sandbox never
// enables enforcement. New code must leave both zero; they remain only so old
// call sites fail closed through Artifact validation instead of silently
// changing meaning.
type Request struct {
	Adapter  Identity
	Binary   string
	Args     []string
	Timeout  time.Duration
	Sandbox  bool
	Artifact []byte
	Recipe   string
	Cache    *Cache
}

type Observation struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type Result struct {
	Verified     bool          `json:"verified"`
	BuildID      string        `json:"build_id"`
	BinarySHA256 string        `json:"binary_sha256"`
	Observed     []Observation `json:"observed,omitempty"`
	Reason       string        `json:"reason"`
	Adapter      Identity      `json:"adapter"`
	Recipe       string        `json:"recipe"`
	Scope        string        `json:"scope"`
}

func failed(res Result, reason string) (Result, error) {
	res.Verified, res.Reason = false, reason
	return res, &Unsupported{Reason: reason}
}

var identityRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var recipeRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,100}-v[1-9][0-9]{0,5}$`)
var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BuildID encodes a digest in the existing hosted/binding identity alphabet.
// Version-label records and the obsolete sha256: form are never auto-migrated.
func BuildID(digest string) (string, error) {
	if !digestRE.MatchString(digest) {
		return "", &Unsupported{Reason: "invalid_digest"}
	}
	return "sha256-" + digest, nil
}

func interrupted(ctx context.Context, res Result) (Result, error) {
	reason := "cancelled"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		reason = "deadline_exceeded"
	}
	return failed(res, reason)
}

func identify(ctx context.Context, req Request) (Result, error) {
	if ctx.Err() != nil {
		return interrupted(ctx, Result{})
	}
	if req.Timeout < 0 || !identityRE.MatchString(req.Adapter.Harness) || !identityRE.MatchString(req.Adapter.Entrypoint) || !recipeRE.MatchString(req.Recipe) {
		return failed(Result{}, "invalid_request")
	}
	if req.Adapter.Adapter != envpatch.AdapterGeneric {
		return failed(Result{}, "adapter_unsupported")
	}
	if len(req.Args) != 0 {
		return failed(Result{}, "unversioned_invocation")
	}
	if len(req.Artifact) == 0 {
		return failed(Result{}, "artifact_snapshot_required")
	}
	if len(req.Artifact) > maxArtifactBytes {
		return failed(Result{}, "artifact_too_large")
	}
	// Accept only native executable containers, not #! scripts/interpreters with
	// external programs. Dependency closure remains a qualification prerequisite.
	if !nativeArtifact(req.Artifact) {
		return failed(Result{}, "runtime_closure_unsupported")
	}
	h := sha256.New()
	for offset := 0; offset < len(req.Artifact); offset += 64 * 1024 {
		if ctx.Err() != nil {
			return interrupted(ctx, Result{})
		}
		end := offset + 64*1024
		if end > len(req.Artifact) {
			end = len(req.Artifact)
		}
		_, _ = h.Write(req.Artifact[offset:end])
	}
	if ctx.Err() != nil {
		return interrupted(ctx, Result{})
	}
	digest := hex.EncodeToString(h.Sum(nil))
	build, _ := BuildID(digest)
	return Result{BuildID: build, BinarySHA256: digest, Adapter: req.Adapter, Recipe: req.Recipe, Scope: TransportScope}, nil
}

func nativeArtifact(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch string(data[:4]) {
	case "\x7fELF", "\xcf\xfa\xed\xfe", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xfe\xed\xfa\xce", "\xca\xfe\xba\xbe", "\xbe\xba\xfe\xca":
		return true
	}
	return false
}

// bounded applies the request timeout as a child deadline. A negative
// timeout is invalid input, not an expired deadline: it is left for
// identify's invalid_request validation without manufacturing
// expiration. This ordering is shared by Evaluate, Lookup, Probe and
// Verified; known-bad and policy guards still precede it in Evaluate
// and Lookup.
func bounded(ctx context.Context, req Request) (context.Context, context.CancelFunc) {
	if req.Timeout < 0 {
		return ctx, func() {}
	}
	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

// BoundIdentity converts evidenced transport results to a durable consumer
// tuple. It is transport evidence only; child/host authorization remains a
// separate gate. Option-C consumers must use Decision.BoundIdentity instead:
// it covers both qualified and unqualified admissions, while this helper
// covers only allowlisted or observed evidence and never an unqualified
// build.
func (r Result) BoundIdentity() (binding.AdapterIdentity, error) {
	build, err := BuildID(r.BinarySHA256)
	if err != nil || !r.Verified || (r.Reason != "allowlisted" && r.Reason != "proxy_attempt_observed") || r.BuildID != build || r.Scope != TransportScope || r.Adapter.Adapter != envpatch.AdapterGeneric || !identityRE.MatchString(r.Adapter.Harness) || !identityRE.MatchString(r.Adapter.Entrypoint) || !recipeRE.MatchString(r.Recipe) {
		return binding.AdapterIdentity{}, &Unsupported{Reason: "invalid_evidence"}
	}
	return binding.AdapterIdentity{Adapter: r.Adapter.Adapter, Harness: r.Adapter.Harness, Build: build, Entrypoint: r.Adapter.Entrypoint}, nil
}

// Probe never launches through os/exec. A throwaway HOME, sandbox-exec and a
// numeric process group cannot enforce the required descriptor, IPC, process
// tree and bounded-cleanup guarantees. No unsafe fallback is provided.
func Probe(ctx context.Context, req Request) (Result, error) {
	ctx, cancel := bounded(ctx, req)
	defer cancel()
	res, err := identify(ctx, req)
	if err != nil {
		return res, err
	}
	return qualificationUnavailable(ctx, req, res, runtime.GOOS)
}

func qualificationUnavailable(ctx context.Context, req Request, res Result, platform string) (Result, error) {
	if ctx.Err() != nil {
		return interrupted(ctx, res)
	}
	recipe, ok := recipes[req.Recipe]
	if !ok || recipe.Harness != req.Adapter.Harness || recipe.Entrypoint != req.Adapter.Entrypoint {
		return failed(res, "recipe_unsupported")
	}
	if recipe.Unavailable != "" {
		return failed(res, recipe.Unavailable)
	}
	switch platform {
	case "linux":
		return failed(res, "namespace_supervisor_required")
	case "darwin":
		return failed(res, "secure_supervisor_required")
	default:
		return failed(res, "platform_unsupported")
	}
}
