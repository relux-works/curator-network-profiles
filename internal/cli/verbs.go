// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/catalog"
	"github.com/relux-works/curator-network-profiles/pkg/envpatch"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

type patchDoc struct {
	Adapter string          `json:"adapter"`
	Unset   []string        `json:"unset"`
	Set     []envpatch.Pair `json:"set"`
}

func patchDocOf(p envpatch.Patch) patchDoc {
	return patchDoc{Adapter: envpatch.AdapterGeneric, Unset: p.UnsetNames(), Set: p.SetLiterals()}
}

type confirmation struct {
	Confirmed   bool       `json:"confirmed"`
	Digest      string     `json:"digest,omitempty"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}

func confirmationOf(cat *catalog.Catalog, name, digest string) confirmation {
	d, at, ok := cat.ConfirmedAt(name)
	if !ok {
		return confirmation{}
	}
	return confirmation{Confirmed: d == digest, Digest: d, ConfirmedAt: &at}
}

func (c confirmation) human() string {
	switch {
	case c.Confirmed:
		return "yes (" + c.ConfirmedAt.UTC().Format(time.RFC3339) + ")"
	case c.Digest != "":
		return "no (content changed since it was confirmed at " + netprofile.ShortDigest(c.Digest) + ")"
	default:
		return "no"
	}
}

func (a *app) list(args []string) int {
	fs := a.flagSet("list")
	if _, code, ok := a.operands(fs, args, 0, 0); !ok {
		return code
	}
	cat, err := catalog.Load(a.deps.Env)
	if err != nil {
		return a.fail(err)
	}
	type row struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		Endpoint  string `json:"endpoint"`
		Digest    string `json:"digest"`
		Confirmed bool   `json:"confirmed"`
		Default   bool   `json:"default"`
	}
	rows := []row{}
	def := ""
	if cat.File != nil {
		def = cat.File.Default
		for _, name := range cat.File.Names() {
			p, _ := cat.File.Lookup(name)
			d := netprofile.Digest(p)
			rows = append(rows, row{name, p.Kind, p.Endpoint, d, cat.Confirmed(name, d), name == def})
		}
	}
	if a.json {
		a.emit(struct {
			Schema   string              `json:"schema"`
			OK       bool                `json:"ok"`
			Default  string              `json:"default"`
			Profiles []row               `json:"profiles"`
			Bindings netprofile.Bindings `json:"bindings"`
		}{SchemaList, true, def, rows, bindingsOf(cat.File, "")})
		return ExitOK
	}
	if len(rows) == 0 {
		fmt.Fprintln(a.deps.Stdout, "no network profiles in ~/.curator/network.toml")
		a.printBindings(bindingsOf(cat.File, ""))
		return ExitOK
	}
	w := tabwriter.NewWriter(a.deps.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tKIND\tENDPOINT\tDIGEST\tCONFIRMED\tDEFAULT")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Kind, r.Endpoint, netprofile.ShortDigest(r.Digest), yesNo(r.Confirmed), mark(r.Default))
	}
	_ = w.Flush()
	a.printBindings(bindingsOf(cat.File, ""))
	return ExitOK
}

func bindingsOf(file *netprofile.File, network string) netprofile.Bindings {
	b := netprofile.Bindings{Profiles: map[string]string{}}
	if file != nil {
		for profile, target := range file.Bindings.Profiles {
			if network == "" || target == network {
				b.Profiles[profile] = target
			}
		}
	}
	return b
}

func (a *app) printBindings(b netprofile.Bindings) {
	if len(b.Profiles) == 0 {
		return
	}
	names := make([]string, 0, len(b.Profiles))
	for name := range b.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintln(a.deps.Stdout, "profile bindings (operator-local):")
	for _, name := range names {
		fmt.Fprintf(a.deps.Stdout, "  %s -> %s\n", name, b.Profiles[name])
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func mark(b bool) string {
	if b {
		return "*"
	}
	return ""
}

func (a *app) show(args []string) int {
	fs := a.flagSet("show")
	pos, code, ok := a.operands(fs, args, 1, 1)
	if !ok {
		return code
	}
	name := pos[0]
	cat, err := catalog.Load(a.deps.Env)
	if err != nil {
		return a.fail(err)
	}
	p, found := cat.File.Lookup(name)
	if !found {
		return a.fail(refusal.New(refusal.CodeProfileUnknown, name, "no such network profile on this machine"))
	}
	digest := netprofile.Digest(p)
	conf := confirmationOf(cat, name, digest)
	patch := envpatch.Generic{}.Patch(p)
	isDefault := cat.File.Default == name
	if a.json {
		a.emit(struct {
			Schema       string              `json:"schema"`
			OK           bool                `json:"ok"`
			Profile      netprofile.Profile  `json:"profile"`
			Digest       string              `json:"digest"`
			Default      bool                `json:"default"`
			Confirmation confirmation        `json:"confirmation"`
			Patch        patchDoc            `json:"patch"`
			Bindings     netprofile.Bindings `json:"bindings"`
		}{SchemaShow, true, p, digest, isDefault, conf, patchDocOf(patch), bindingsOf(cat.File, name)})
		return ExitOK
	}
	out := a.deps.Stdout
	fmt.Fprintf(out, "name:            %s\n", p.Name)
	fmt.Fprintf(out, "kind:            %s\n", p.Kind)
	fmt.Fprintf(out, "endpoint:        %s\n", p.Endpoint)
	fmt.Fprintf(out, "bypass_hosts:    %s\n", strings.Join(p.BypassHosts, ", "))
	target := p.ProbeTarget
	if p.Kind == netprofile.KindDirect {
		target = "(none: direct skips all probes)"
	} else if target == "" {
		target = "(none: check --probe and the launch preflight test TCP only)"
	}
	fmt.Fprintf(out, "probe_target:    %s\n", target)
	fmt.Fprintf(out, "credential_mode: %s\n", p.CredentialMode)
	fmt.Fprintf(out, "digest:          %s\n", digest)
	fmt.Fprintf(out, "confirmed:       %s\n", conf.human())
	fmt.Fprintf(out, "default:         %s\n", yesNo(isDefault))
	a.printBindings(bindingsOf(cat.File, name))
	fmt.Fprintf(out, "patch (%s):\n", envpatch.AdapterGeneric)
	fmt.Fprintf(out, "  unset: %s\n", strings.Join(patch.Unset, " "))
	for _, kv := range patch.Set {
		fmt.Fprintf(out, "  set:   %s=%s\n", kv.Name, kv.Value)
	}
	return ExitOK
}

func (a *app) add(args []string) int {
	fs := a.flagSet("add")
	direct := fs.Bool("direct", false, "clear inherited proxies without setting a proxy")
	endpoint := fs.String("endpoint", "", "proxy endpoint http://host:port")
	bypass := fs.String("bypass", "", "comma-separated extra bypass hosts (localhost, 127.0.0.1 and ::1 are always added)")
	target := fs.String("probe-target", "", "host:port for CONNECT+TLS probes")
	pos, code, ok := a.operands(fs, args, 1, 1)
	if !ok {
		return code
	}
	name := pos[0]
	conflict := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "endpoint" || f.Name == "bypass" || f.Name == "probe-target" {
			conflict = true
		}
	})
	if *direct && conflict {
		return a.usage("add: --direct conflicts with --endpoint, --bypass and --probe-target")
	}
	if !*direct && strings.TrimSpace(*endpoint) == "" {
		return a.usage("add: --endpoint is required")
	}
	var hosts []string
	for _, h := range strings.Split(*bypass, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	in := netprofile.Input{Kind: netprofile.KindDirect}
	if !*direct {
		in = netprofile.Input{Kind: netprofile.KindExternalHTTPProxy, Endpoint: *endpoint, BypassHosts: netprofile.WithRequiredBypass(hosts), ProbeTarget: *target}
	}
	p, err := netprofile.Normalize(name, in)
	if err != nil {
		return a.fail(err)
	}
	paths, err := store.PathsFromEnv(a.deps.Env)
	if err != nil {
		return a.fail(err)
	}
	if err := store.Edit(paths, func(e *store.Editor) error {
		// Refuse duplicate names before touching their current confirmation.
		file, _, err := store.Read(paths)
		if err != nil {
			return err
		}
		if _, found := file.Lookup(name); found {
			return refusal.New(refusal.CodeConfigurationConflict, name, "profile already exists; remove it first")
		}
		ledger, err := confirm.Read(paths.Ledger)
		if err != nil {
			return err
		}
		// Clear stale confirmation before widening the catalog. If cleanup fails,
		// no profile is added; if Add fails, losing a stale entry remains safe.
		if ledger.Delete(name) {
			if err := confirm.Write(paths.Ledger, ledger); err != nil {
				return err
			}
		}
		return e.Add(p)
	}); err != nil {
		return a.fail(err)
	}
	digest := netprofile.Digest(p)
	if a.json {
		a.emit(struct {
			Schema              string             `json:"schema"`
			OK                  bool               `json:"ok"`
			Name                string             `json:"name"`
			Digest              string             `json:"digest"`
			PendingConfirmation bool               `json:"pending_confirmation"`
			Profile             netprofile.Profile `json:"profile"`
		}{SchemaAdd, true, name, digest, true, p})
		return ExitOK
	}
	fmt.Fprintf(a.deps.Stdout, "added %s (digest %s)\npending confirmation: run `curator network confirm %s` from a terminal\n", name, digest, name)
	return ExitOK
}

func (a *app) remove(args []string) int {
	fs := a.flagSet("remove")
	pos, code, ok := a.operands(fs, args, 1, 1)
	if !ok {
		return code
	}
	name := pos[0]
	paths, err := store.PathsFromEnv(a.deps.Env)
	if err != nil {
		return a.fail(err)
	}
	// A read-only refusal must not create a namespace or edit lock. A stale
	// ledger entry still needs cleanup under Edit; re-read it inside the lock.
	if _, err := os.Lstat(paths.File); errors.Is(err, os.ErrNotExist) {
		ledger, err := confirm.Read(paths.Ledger)
		if err != nil {
			return a.fail(err)
		}
		if _, stale := ledger.Entry(name); !stale {
			return a.fail(refusal.New(refusal.CodeProfileUnknown, name, "no such network profile on this machine"))
		}
	}
	dropped, removed := false, false
	err = store.Edit(paths, func(e *store.Editor) error {
		// Validate the ledger before changing the catalog. These two atomic
		// writes are ordered but not a cross-file transaction.
		ledger, err := confirm.Read(paths.Ledger)
		if err != nil {
			return err
		}
		if err := e.Remove(name); err != nil {
			code, _ := refusal.CodeOf(err)
			if _, stale := ledger.Entry(name); code != refusal.CodeProfileUnknown || !stale {
				return err
			}
		} else {
			removed = true
		}
		dropped = ledger.Delete(name)
		if dropped {
			return confirm.Write(paths.Ledger, ledger)
		}
		return nil
	})
	if err != nil {
		return a.fail(err)
	}
	if a.json {
		a.emit(struct {
			Schema              string `json:"schema"`
			OK                  bool   `json:"ok"`
			Name                string `json:"name"`
			Removed             bool   `json:"removed"`
			ConfirmationDropped bool   `json:"confirmation_dropped"`
		}{SchemaRemove, true, name, removed, dropped})
		return ExitOK
	}
	if !removed {
		fmt.Fprintf(a.deps.Stdout, "dropped stale confirmation entry for %s (profile already absent)\n", name)
		return ExitOK
	}
	fmt.Fprintf(a.deps.Stdout, "removed %s", name)
	if dropped {
		fmt.Fprint(a.deps.Stdout, " (confirmation entry dropped)")
	}
	fmt.Fprintln(a.deps.Stdout)
	return ExitOK
}

type checkResult struct {
	Name      string        `json:"name"`
	Kind      string        `json:"kind"`
	Endpoint  string        `json:"endpoint"`
	Digest    string        `json:"digest"`
	Confirmed bool          `json:"confirmed"`
	OK        bool          `json:"ok"`
	Probe     *probe.Result `json:"probe,omitempty"`
	Error     *errorBody    `json:"error,omitempty"`
}

// check validates without any network call; --probe is the explicit
// network call (TCP, then CONNECT and TLS to --target or the profile's
// probe_target). TODO(decision): a failed check is reported inside the
// check document (ok=false, per-profile error) rather than as the
// error-v1 envelope, so the three probe facts are not lost.
func (a *app) check(args []string) int {
	fs := a.flagSet("check")
	all := fs.Bool("all", false, "check every profile")
	doProbe := fs.Bool("probe", false, "TCP, CONNECT and TLS probe (the only network call)")
	target := fs.String("target", "", "CONNECT target host:port (default: the profile's probe_target)")
	timeout := fs.Duration("timeout", probe.DefaultTimeout, "probe deadline")
	pos, code, ok := a.operands(fs, args, 0, 1)
	if !ok {
		return code
	}
	if len(pos) == 1 && *all {
		return a.usage("check: give a name or --all, not both")
	}
	if *target != "" {
		if _, err := netprofile.NormalizeProbeTarget(*target); err != nil {
			return a.usage("check: --target: " + err.Error())
		}
	}
	cat, err := catalog.Load(a.deps.Env)
	if err != nil {
		return a.fail(err)
	}
	var names []string
	if len(pos) == 1 {
		if _, found := cat.File.Lookup(pos[0]); !found {
			return a.fail(refusal.New(refusal.CodeProfileUnknown, pos[0], "no such network profile on this machine"))
		}
		names = pos
	} else {
		names = cat.File.Names()
	}
	results := []checkResult{}
	allOK := true
	for _, name := range names {
		p, _ := cat.File.Lookup(name)
		digest := netprofile.Digest(p)
		r := checkResult{Name: name, Kind: p.Kind, Endpoint: p.Endpoint, Digest: digest, Confirmed: cat.Confirmed(name, digest), OK: true}
		if *doProbe && p.Kind == netprofile.KindDirect {
			r.Probe = &probe.Result{TCP: probe.StatusSkipped, Connect: probe.StatusSkipped, TLS: probe.StatusSkipped, CheckedAt: a.deps.Now()}
		} else if *doProbe {
			t := p.ProbeTarget
			if *target != "" {
				t, _ = netprofile.NormalizeProbeTarget(*target)
			}
			res, err := a.deps.Prober.Probe(a.ctx, probe.Request{Subject: name, Endpoint: p.Endpoint, Target: t, Timeout: *timeout})
			r.Probe = &res
			if err != nil {
				body := bodyOf(err)
				r.Error = &body
				r.OK = false
				allOK = false
			}
		}
		results = append(results, r)
	}
	if !a.json {
		for _, r := range results {
			fmt.Fprintf(a.deps.Stdout, "%s: valid (digest %s), confirmed: %s", r.Name, netprofile.ShortDigest(r.Digest), yesNo(r.Confirmed))
			if r.Kind == netprofile.KindDirect {
				fmt.Fprint(a.deps.Stdout, ", kind: direct")
			}
			fmt.Fprintln(a.deps.Stdout)
			if r.Probe != nil {
				fmt.Fprintf(a.deps.Stdout, "%s: probe %s: %s\n", r.Name, r.Endpoint, probeLine(r.Probe))
			}
		}
		if len(results) == 0 {
			fmt.Fprintln(a.deps.Stdout, "no network profiles in ~/.curator/network.toml")
		}
	}
	for _, r := range results {
		if r.Error != nil {
			a.diag(r.Error.Code, strings.TrimPrefix(r.Error.Message, r.Error.Code+": "))
		}
	}
	if a.json {
		a.emit(struct {
			Schema  string        `json:"schema"`
			OK      bool          `json:"ok"`
			Probe   bool          `json:"probe"`
			Results []checkResult `json:"results"`
		}{SchemaCheck, allOK, *doProbe, results})
	}
	if !allOK {
		return ExitRefused
	}
	return ExitOK
}

func probeLine(r *probe.Result) string {
	parts := []string{"tcp " + string(r.TCP)}
	connect := "connect " + string(r.Connect)
	if r.ConnectStatus != 0 {
		connect += fmt.Sprintf(" (%d)", r.ConnectStatus)
	}
	parts = append(parts, connect, "tls "+string(r.TLS))
	if r.Target != "" {
		parts = append(parts, "target "+r.Target)
	}
	line := strings.Join(parts, ", ")
	if r.Detail != "" {
		line += " — " + r.Detail
	}
	return line
}

// confirm records the current digest of each pending profile after the
// operator, at a terminal and outside any agent session, types `yes`. The
// prompt holds no lock; the catalog is revalidated and the ledger re-read
// under store.WithCatalogLock before recording exactly the digests shown.
func (a *app) confirm(args []string) int {
	fs := a.flagSet("confirm")
	pos, code, ok := a.operands(fs, args, 0, -1)
	if !ok {
		return code
	}
	if err := confirm.Guard(a.deps.Env, a.deps.IsTerminal()); err != nil {
		return a.fail(err)
	}
	paths, err := store.PathsFromEnv(a.deps.Env)
	if err != nil {
		return a.fail(err)
	}
	file, shownCatalog, err := store.Read(paths)
	if err != nil {
		return a.fail(err)
	}
	ledger, err := confirm.Read(paths.Ledger)
	if err != nil {
		return a.fail(err)
	}
	names := pos
	if len(names) == 0 {
		names = file.Names()
	}
	type pending struct {
		Name        string    `json:"name"`
		Digest      string    `json:"digest"`
		ConfirmedAt time.Time `json:"confirmed_at"`
		previous    string
		profile     netprofile.Profile
	}
	var todo []pending
	var unchanged []string
	for _, name := range names {
		p, found := file.Lookup(name)
		if !found {
			return a.fail(refusal.New(refusal.CodeProfileUnknown, name, "no such network profile on this machine"))
		}
		d := netprofile.Digest(p)
		if ledger.Confirmed(name, d) {
			unchanged = append(unchanged, name)
			continue
		}
		prev, _ := ledger.Entry(name)
		todo = append(todo, pending{Name: name, Digest: d, previous: prev.Digest, profile: p})
	}
	if unchanged == nil {
		unchanged = []string{}
	}
	if len(todo) == 0 {
		if a.json {
			a.emit(struct {
				Schema    string    `json:"schema"`
				OK        bool      `json:"ok"`
				Confirmed []pending `json:"confirmed"`
				Unchanged []string  `json:"unchanged"`
			}{SchemaConfirm, true, []pending{}, unchanged})
		} else {
			fmt.Fprintf(a.deps.Stdout, "nothing to confirm: %d profile(s) already confirmed at their current digest\n", len(unchanged))
		}
		return ExitOK
	}
	prompt := a.deps.Stdout
	if a.json {
		prompt = a.deps.Stderr
	}
	fmt.Fprintln(prompt, "These network profiles take effect once confirmed (adding one is a widening entry, trust §10):")
	for _, t := range todo {
		state := "new"
		if t.previous != "" {
			state = "changed since " + netprofile.ShortDigest(t.previous)
		}
		fmt.Fprintf(prompt, "  %s  %s  %s  (%s)\n", t.Name, t.profile.Endpoint, t.Digest, state)
	}
	fmt.Fprintf(prompt, "Type `yes` to confirm %d profile(s): ", len(todo))
	line, _ := bufio.NewReader(a.deps.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		fmt.Fprintln(prompt)
		return a.fail(refusal.New(refusal.CodeConfirmRefused, "operator", "not confirmed (the answer was not `yes`)"))
	}
	if err := store.WithCatalogLock(paths, func() error {
		currentCatalog, err := os.ReadFile(paths.File)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "cannot read")
		}
		// The preview was validated already. Compare its bytes directly so
		// even deletion or a malformed manual edit gets the change conflict.
		if !bytes.Equal(shownCatalog, currentCatalog) {
			return refusal.New(refusal.CodeConfigurationConflict, netprofile.FileName, "catalog changed during confirm; run confirm again")
		}
		// Another editor may have updated the ledger during the prompt.
		// Preserve its entries instead of writing the preview's stale copy.
		ledger, err := confirm.Read(paths.Ledger)
		if err != nil {
			return err
		}
		now := a.deps.Now().UTC()
		for i := range todo {
			todo[i].ConfirmedAt = now
			ledger.Set(todo[i].Name, todo[i].Digest, now)
		}
		return confirm.Write(paths.Ledger, ledger)
	}); err != nil {
		return a.fail(err)
	}
	if a.json {
		a.emit(struct {
			Schema    string    `json:"schema"`
			OK        bool      `json:"ok"`
			Confirmed []pending `json:"confirmed"`
			Unchanged []string  `json:"unchanged"`
		}{SchemaConfirm, true, todo, unchanged})
		return ExitOK
	}
	for _, t := range todo {
		fmt.Fprintf(a.deps.Stdout, "confirmed %s at %s\n", t.Name, t.Digest)
	}
	return ExitOK
}
