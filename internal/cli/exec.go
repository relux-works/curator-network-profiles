// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/envutil"
	"github.com/relux-works/curator-network-profiles/pkg/binding"
	"github.com/relux-works/curator-network-profiles/pkg/catalog"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

// exec is the slice-A launch path: resolve (explicit) → validate →
// preflight (proxy TCP; CONNECT+TLS when probe_target is set; direct skips) → bind →
// Apply to the inherited environment → Deps.Exec. Any failure refuses
// before exec; there is no fallback to direct. The command is resolved
// through PATH of the inherited (unpatched) environment; the patch only
// touches proxy variables, so both are the same PATH. Dry runs skip lookup
// and preflight, and record all probe steps as skipped. Direct also skips
// preflight on a real launch.
func (a *app) exec(args []string) int {
	sep := -1
	for i, arg := range args {
		if arg == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return a.usage("exec: the command follows `--`: exec <name> [flags] -- <command> [arguments...]")
	}
	front, command := args[:sep], args[sep+1:]
	if len(command) == 0 {
		return a.usage("exec: no command after `--`")
	}
	fs := a.flagSet("exec")
	timeout := fs.Duration("preflight-timeout", probe.DefaultTimeout, "preflight deadline")
	dryRun := fs.Bool("dry-run", false, "print the binding record and the patch; do not exec")
	pos, code, ok := a.operands(fs, front, 1, 1)
	if !ok {
		return code
	}
	name := pos[0]
	if err := netprofile.ValidateName(name); err != nil {
		return a.usage("exec: invalid network profile name")
	}

	cat, err := catalog.Load(a.deps.Env)
	if err != nil {
		return a.fail(err)
	}
	res, err := cat.Resolve(resolve.Request{Explicit: name})
	if err != nil {
		return a.fail(err)
	}
	if !res.Managed || res.Selection.Origin != resolve.OriginExplicit {
		return a.usage("exec: an explicit managed network profile is required")
	}
	pr := probe.Result{TCP: probe.StatusSkipped, Connect: probe.StatusSkipped, TLS: probe.StatusSkipped, CheckedAt: a.deps.Now()}
	var path string
	if !*dryRun {
		path, err = lookPath(command[0], a.deps.Env)
		if err != nil {
			return a.usage("exec: " + err.Error())
		}
		if res.Profile.Kind != netprofile.KindDirect {
			pr, err = a.deps.Prober.Probe(a.ctx, probe.Request{Subject: name, Endpoint: res.Profile.Endpoint, Target: res.Profile.ProbeTarget, Timeout: *timeout})
			if err != nil {
				return a.fail(err)
			}
		}
	}
	entrypoint := filepath.Base(command[0])
	if !refusal.PlainSubject(entrypoint) {
		entrypoint = "<command>"
	}
	patch := envpatch.Generic{}.Patch(res.Profile)
	b := binding.Binding{
		ProfileRef:       res.Selection.ProfileRef,
		ProfileDigest:    res.Digest,
		AdapterIdentity:  binding.AdapterIdentity{Adapter: envpatch.AdapterGeneric, Harness: "exec", Build: "", Entrypoint: entrypoint},
		Assurance:        res.Assurance,
		ResolvedEndpoint: res.Profile.Endpoint,
		EnvPatch:         patch,
	}
	record := b.Record(string(res.Selection.Origin), &binding.ProbeRecord{TCP: string(pr.TCP), Connect: string(pr.Connect), TLS: string(pr.TLS), CheckedAt: pr.CheckedAt})

	if *dryRun {
		if a.json {
			a.emit(struct {
				Schema     string         `json:"schema"`
				OK         bool           `json:"ok"`
				DryRun     bool           `json:"dry_run"`
				Binding    binding.Record `json:"binding"`
				Patch      patchDoc       `json:"patch"`
				Argc       int            `json:"argc"`
				Entrypoint string         `json:"entrypoint"`
			}{SchemaExec, true, true, record, patchDocOf(patch), len(command), entrypoint})
			return ExitOK
		}
		out := a.deps.Stdout
		fmt.Fprintf(out, "dry run: would exec %s (+%d args)\n", entrypoint, len(command)-1)
		fmt.Fprintf(out, "binding record:\n")
		fmt.Fprintf(out, "  profile_ref:      %s\n", record.ProfileRef)
		fmt.Fprintf(out, "  profile_digest:   %s\n", record.ProfileDigest)
		fmt.Fprintf(out, "  adapter_identity: adapter=%s harness=%s build=%q entrypoint=%s\n", record.AdapterIdentity.Adapter, record.AdapterIdentity.Harness, record.AdapterIdentity.Build, record.AdapterIdentity.Entrypoint)
		fmt.Fprintf(out, "  assurance:        %s\n", record.Assurance)
		fmt.Fprintf(out, "  origin:           %s\n", record.Origin)
		fmt.Fprintf(out, "  probe:            tcp %s, connect %s, tls %s at %s\n", record.Probe.TCP, record.Probe.Connect, record.Probe.TLS, record.Probe.CheckedAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(out, "patch (%s):\n", envpatch.AdapterGeneric)
		fmt.Fprintf(out, "  unset: %s\n", strings.Join(patch.Unset, " "))
		for _, kv := range patch.Set {
			fmt.Fprintf(out, "  set:   %s=%s\n", kv.Name, kv.Value)
		}
		return ExitOK
	}

	env := patch.Apply(a.deps.Env)
	fmt.Fprintf(a.deps.Stderr, "%s: network=%s digest=%s adapter=%s preflight=tcp %s, connect %s, tls %s\n",
		Name, record.ProfileRef, record.ProfileDigest, record.AdapterIdentity.Adapter, pr.TCP, pr.Connect, pr.TLS)
	if err := a.deps.Exec(path, command, env); err != nil {
		return a.usage("exec: cannot execute command")
	}
	// Exec replaces the process; a return without error cannot happen in
	// production. A test double that returns nil ends the run here.
	return ExitOK
}

// lookPath resolves file through PATH of env (never the process
// environment). A name containing a separator is used as given.
func lookPath(file string, env []string) (string, error) {
	if file == "" {
		return "", errors.New("empty command")
	}
	if strings.Contains(file, string(filepath.Separator)) {
		if executable(file) {
			return file, nil
		}
		return "", errors.New("command is not executable")
	}
	path, _ := envutil.Lookup(env, "PATH")
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, file)
		if executable(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("command not found in PATH")
}

func executable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}
