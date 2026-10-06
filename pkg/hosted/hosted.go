// SPDX-License-Identifier: Apache-2.0

package hosted

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/catalog"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

// CatalogLoader loads only the trusted destination operator's catalog/ledger.
type CatalogLoader func(context.Context, string) (*catalog.Catalog, error)

// LedgerLoader optionally replaces the loaded catalog's confirmations, for a
// host with a separate trusted authorization store. It must never auto-confirm.
type LedgerLoader func(context.Context, string) (resolve.Confirmations, error)

// AdapterVerifier must verify the exact tuple and child scope against local
// evidence. Generic environment compatibility alone is not authorization.
type AdapterVerifier func(context.Context, binding.AdapterIdentity, string) error

// AdapterVerifierWithProfile verifies the exact tuple, child scope and
// adapter policy against the destination's resolved profile snapshot. It
// is the option-C path: the host passes its own resolved profile
// (including SensitiveEgress) so the caller evaluates the same snapshot
// without a second independently changing catalog read. Callers evaluate
// the snapshot with adapterprobe.Evaluate (loaded known-bad state plus
// the passed sensitivity), check the admitted Decision, convert it with
// Decision.BoundIdentity, and retain the independent child-scope gate.
// The legacy AdapterVerifier remains for callers that have not migrated;
// new code must use this profile-aware form.
type AdapterVerifierWithProfile func(ctx context.Context, id binding.AdapterIdentity, assurance string, profile netprofile.Profile) error

// Options are trusted host inputs, never fields supplied by the launch payload.
type Options struct {
	OperatorHome string
	LoadCatalog  CatalogLoader
	LoadLedger   LedgerLoader
	// Adapter defaults to envpatch.Generic. Its identity must match Identity.
	Adapter       envpatch.Adapter
	Identity      binding.AdapterIdentity
	VerifyAdapter AdapterVerifier
	// VerifyAdapterWithProfile is the option-C verifier: when set it
	// replaces VerifyAdapter and receives the resolved profile snapshot.
	VerifyAdapterWithProfile AdapterVerifierWithProfile
	RequiredAssurance        string
	// Allowlist: nil allows all catalog entries; a non-nil empty list denies all.
	Allowlist   []string
	EngineHosts []string
	// EnvNames is checked before any preflight. Hosts also check later overlays.
	EnvNames []string
	// Preflight is true only for real proxy starts/restarts. Plans, dry runs
	// and live reattach set false; direct always skips probing.
	Preflight bool
	Prober    probe.Prober
	// ProbeTimeout defaults to probe.DefaultTimeout and is capped at 30 seconds.
	ProbeTimeout time.Duration
}

var identityRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// ResolveForHost authorizes precisely the carried ref on the destination,
// compares the expected digest, verifies the adapter, and optionally probes.
// The returned Binding is volatile; persist only the sanitized Record. On any
// refusal both outputs are zero. No ambient env or destination default selects
// a substitute, and no confirmation is written.
func ResolveForHost(ctx context.Context, c Carrier, opts Options) (binding.Binding, binding.Record, error) {
	fail := func(err error) (binding.Binding, binding.Record, error) {
		return binding.Binding{}, binding.Record{}, err
	}
	if err := c.Validate(); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if !filepath.IsAbs(opts.OperatorHome) || strings.ContainsRune(opts.OperatorHome, 0) {
		return fail(refusal.New(refusal.CodeFileUnreadable, "network.toml", "an absolute operator HOME is required"))
	}
	load := opts.LoadCatalog
	if load == nil {
		load = func(_ context.Context, home string) (*catalog.Catalog, error) {
			return catalog.Load([]string{"HOME=" + home})
		}
	}
	cat, err := load(ctx, opts.OperatorHome)
	if err != nil {
		return fail(boundaryError(err, refusal.CodeFileUnreadable, c.Ref, "cannot load host network catalog"))
	}
	if cat == nil {
		return fail(refusal.New(refusal.CodeFileUnreadable, "network.toml", "catalog loader returned no catalog"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	var ledger resolve.Confirmations = cat
	if opts.LoadLedger != nil {
		ledger, err = opts.LoadLedger(ctx, opts.OperatorHome)
		if err != nil {
			return fail(boundaryError(err, refusal.CodeFileUnreadable, c.Ref, "cannot load host confirmations"))
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	res, err := resolve.Resolve(cat.File, ledger, resolve.Request{
		Explicit: c.Ref, RequiredAssurance: opts.RequiredAssurance,
		Allowed: opts.Allowlist, EngineHosts: opts.EngineHosts,
	})
	if err != nil {
		return fail(boundaryError(err, refusal.CodeProfileDenied, c.Ref, "host network authorization refused"))
	}
	if res.Digest != c.ExpectedDigest {
		return fail(refusal.New(refusal.CodeProfileDrift, c.Ref, "host profile differs from the expected digest"))
	}
	adapter := opts.Adapter
	if adapter == nil {
		adapter = envpatch.Generic{}
	}
	id := opts.Identity
	if !identityRE.MatchString(id.Adapter) || !identityRE.MatchString(id.Harness) || !identityRE.MatchString(id.Build) || !identityRE.MatchString(id.Entrypoint) || id.Adapter != adapter.Identity() || (opts.VerifyAdapter == nil && opts.VerifyAdapterWithProfile == nil) {
		return fail(refusal.New(refusal.CodeScopeUnsupported, c.Ref, "a locally verified adapter tuple is required"))
	}
	if opts.VerifyAdapterWithProfile != nil {
		if err := opts.VerifyAdapterWithProfile(ctx, id, res.Assurance, res.Profile); err != nil {
			return fail(refusal.New(refusal.CodeScopeUnsupported, c.Ref, "host adapter or child scope is unsupported"))
		}
	} else if err := opts.VerifyAdapter(ctx, id, res.Assurance); err != nil {
		return fail(refusal.New(refusal.CodeScopeUnsupported, c.Ref, "host adapter or child scope is unsupported"))
	}
	if err := ValidateEnvNames(opts.EnvNames); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	b := binding.Binding{ProfileRef: c.Ref, ProfileDigest: res.Digest, AdapterIdentity: id,
		Assurance: res.Assurance, ResolvedEndpoint: res.Profile.Endpoint, EnvPatch: adapter.Patch(res.Profile)}
	var pr *binding.ProbeRecord
	if opts.Preflight && res.Profile.Kind != netprofile.KindDirect {
		timeout := opts.ProbeTimeout
		if timeout <= 0 {
			timeout = probe.DefaultTimeout
		}
		if timeout > 30*time.Second {
			timeout = 30 * time.Second
		}
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		p := opts.Prober
		if p == nil {
			p = &probe.Dialer{}
		}
		raw, err := p.Probe(probeCtx, probe.Request{Subject: c.Ref, Endpoint: res.Profile.Endpoint, Target: res.Profile.ProbeTarget, Timeout: timeout})
		if err != nil {
			return fail(boundaryError(err, refusal.CodeProxyUnreachable, c.Ref, "host network preflight failed"))
		}
		if probeCtx.Err() != nil || raw.TCP != probe.StatusOK || (res.Profile.ProbeTarget != "" && (raw.Connect != probe.StatusOK || raw.TLS != probe.StatusOK)) {
			return fail(refusal.New(refusal.CodeProxyUnreachable, c.Ref, "host network preflight did not establish the required facts"))
		}
		pr = &binding.ProbeRecord{TCP: string(raw.TCP), Connect: string(raw.Connect), TLS: string(raw.TLS), CheckedAt: raw.CheckedAt.UTC()}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	origin, _ := recordOrigin(c.Origin)
	return b, b.Record(string(origin), pr), nil
}

// ApplyFinal preserves untouched order, suppresses every case variant of the
// proxy family, and appends the fresh patch in its declared order LAST. A zero
// Binding is unmanaged and copies the input unchanged. Never overlay afterward.
func ApplyFinal(env []string, b binding.Binding) []string {
	if b.ProfileDigest == "" {
		return envpatch.Unmanaged().Apply(env)
	}
	p := b.EnvPatch
	p.Unset = append(envpatch.UnsetNames(), p.Unset...)
	return p.Apply(env)
}

// ValidateEnvNames refuses proxy-family name replay/overlays in any case. Values
// and supplied names never appear in diagnostics. Call for managed launches.
func ValidateEnvNames(names []string) error {
	for _, name := range names {
		for _, reserved := range envpatch.UnsetNames() {
			if strings.EqualFold(name, reserved) {
				return refusal.New(refusal.CodeConfigurationConflict, "env_names", "proxy-family names are reserved for the network binding")
			}
		}
	}
	return nil
}

// CheckReattach compares digest, all four adapter members and assurance using
// the existing reattach contract, without probing or permitting rerouting.
// Ref/origin/probe differences alone do not change binding equality. Call only
// after re-resolving the original stored ref and its current authorization.
func CheckReattach(stored binding.Record, fresh binding.Binding) error {
	if stored.Schema != binding.SchemaRecord {
		return refusal.New(refusal.CodeScopeUnsupported, "network", "a managed binding record is required for reattach")
	}
	_, err := binding.CheckReattach(stored, fresh, binding.EventReattach, false)
	return err
}

// Loader/prober errors are untrusted diagnostics. Preserve typed network codes
// but project only fixed prose, never paths, endpoints, targets or raw errors.
func boundaryError(err error, fallback, subject, detail string) error {
	code, ok := refusal.CodeOf(err)
	if !ok || !refusal.Valid(code) {
		code = fallback
	}
	return refusal.New(code, subject, detail)
}
