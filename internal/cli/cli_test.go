// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/cli"
	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

const twoProfiles = `schema = "relux-network-profiles-v1"
default = "egress-b"

[networks.egress-a]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18081"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]
probe_target = "probe.invalid:443"

[networks.egress-b]
kind         = "external-http-proxy"
endpoint     = "http://127.0.0.1:18082"
bypass_hosts = ["localhost", "127.0.0.1", "::1"]
`

// fatalProber fails the test when a verb that must not touch the
// network calls it.
type fatalProber struct{ t *testing.T }

func (f fatalProber) Probe(context.Context, probe.Request) (probe.Result, error) {
	f.t.Helper()
	f.t.Fatal("the prober was called by a verb that must make no network call")
	return probe.Result{}, nil
}

// fakeProber answers by endpoint and records calls.
type fakeProber struct {
	mu    sync.Mutex
	fail  map[string]error // endpoint → refusal
	calls []probe.Request
}

func (f *fakeProber) Probe(_ context.Context, req probe.Request) (probe.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	f.mu.Unlock()
	res := probe.Result{Endpoint: req.Endpoint, Target: req.Target, TCP: probe.StatusOK, Connect: probe.StatusSkipped, TLS: probe.StatusSkipped, CheckedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	if req.Target != "" {
		res.Connect, res.TLS, res.ConnectStatus = probe.StatusOK, probe.StatusOK, 200
	}
	if err, ok := f.fail[req.Endpoint]; ok {
		res.TCP, res.Connect, res.TLS = probe.StatusFailed, probe.StatusSkipped, probe.StatusSkipped
		res.Detail = "tcp: connection refused"
		return res, err
	}
	return res, nil
}

type execCall struct {
	path string
	argv []string
	env  []string
}

type fakeExec struct {
	mu    sync.Mutex
	calls []execCall
	err   error
}

func (f *fakeExec) exec(path string, argv, env []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, execCall{path, argv, env})
	return f.err
}

type harness struct {
	t        *testing.T
	home     string
	bin      string
	env      []string
	stdin    string
	terminal bool
	prober   probe.Prober
	exec     *fakeExec
	now      time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return &harness{
		t: t, home: home, bin: bin,
		env:    []string{"HOME=" + home, "PATH=" + bin, "XDG_CONFIG_HOME=" + filepath.Join(home, "xdg")},
		prober: fatalProber{t},
		exec:   &fakeExec{},
		now:    time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}
}

func (h *harness) writeFile(doc string) {
	h.t.Helper()
	dir := filepath.Join(h.home, ".curator")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "network.toml"), []byte(doc), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) confirmAll() {
	h.t.Helper()
	f, err := netprofile.Parse([]byte(twoProfiles))
	if err != nil {
		h.t.Fatal(err)
	}
	l := confirm.Empty()
	for _, name := range f.Names() {
		p, _ := f.Lookup(name)
		l.Set(name, netprofile.Digest(p), h.now)
	}
	// Fixture only: production confirm.Write stays atomic and fsynced.
	data, err := json.Marshal(l)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.home, ".curator", "network.confirmations.json"), data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) tool(name string) string {
	h.t.Helper()
	p := filepath.Join(h.bin, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Run(context.Background(), args, cli.Deps{
		Env: h.env, Stdin: strings.NewReader(h.stdin), Stdout: &stdout, Stderr: &stderr,
		IsTerminal: func() bool { return h.terminal }, Exec: h.exec.exec, Prober: h.prober,
		Now: func() time.Time { return h.now },
	})
	return code, stdout.String(), stderr.String()
}

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return m
}

func wantDiag(t *testing.T, stderr, code, subject string) {
	t.Helper()
	if !strings.HasPrefix(stderr, "curator-network: "+code+": "+subject+": ") {
		t.Fatalf("stderr = %q, want diagnostic %s for %s", stderr, code, subject)
	}
}

func TestUsageAndHelp(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for _, args := range [][]string{nil, {"bogus"}, {"--bogus"}, {"show"}, {"show", "a", "b"}, {"add", "x"}, {"list", "--nope"}, {"remove"}, {"check", "a", "--all"}, {"check", "--target", "nohost"}, {"exec", "a", "cmd"}, {"exec", "a", "--"}, {"exec", "--", "cmd"}} {
		code, stdout, stderr := h.run(args...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "curator-network: usage: ") || !strings.Contains(stderr, "usage: curator-network [--json]") {
			t.Errorf("%v: code %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"list", "-h"}} {
		code, stdout, stderr := h.run(args...)
		if code != 0 || !strings.HasPrefix(stdout, "usage: curator-network") || stderr != "" {
			t.Errorf("%v: code %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	code, stdout, _ := h.run("--version")
	if code != 0 || !regexp.MustCompile(`^curator-network \S+ \(revision \S+(, dirty)?; contract relux-network-profiles-v1\)\n$`).MatchString(stdout) {
		t.Fatalf("version = %d %q", code, stdout)
	}
	code, stdout, _ = h.run("--json", "--version")
	m := decode(t, stdout)
	if code != 0 || m["schema"] != "curator-network-version-v1" || m["ok"] != true || m["contract"] != "relux-network-profiles-v1" || m["name"] != "curator-network" {
		t.Fatalf("json version = %v", m)
	}
	if code, _, _ := h.run("version"); code != 0 {
		t.Fatal("version verb")
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	code, stdout, stderr := h.run("list")
	if code != 0 || stdout != "no network profiles in ~/.curator/network.toml\n" || stderr != "" {
		t.Fatalf("empty list: %d %q %q", code, stdout, stderr)
	}
	code, stdout, _ = h.run("list", "--json")
	m := decode(t, stdout)
	if code != 0 || m["schema"] != "curator-network-list-v1" || len(m["profiles"].([]any)) != 0 {
		t.Fatalf("empty json list: %v", m)
	}
	h.writeFile(twoProfiles)
	code, stdout, _ = h.run("list")
	if code != 0 || !strings.HasPrefix(stdout, "NAME") || !strings.Contains(stdout, "egress-a") || !strings.Contains(stdout, "sha256:1e5912de9e34 ") || !strings.Contains(stdout, "no ") {
		t.Fatalf("list = %q", stdout)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[2], "*") || strings.HasSuffix(lines[1], "*") {
		t.Fatalf("default marker: %q", lines)
	}
	h.confirmAll()
	code, stdout, _ = h.run("--json", "list")
	m = decode(t, stdout)
	profiles := m["profiles"].([]any)
	first := profiles[0].(map[string]any)
	if code != 0 || len(profiles) != 2 || first["name"] != "egress-a" || first["digest"] != "sha256:1e5912de9e3459a12b7365f338d385c1c4c7b4a6b622598e17ed4004d7658699" || first["confirmed"] != true || first["default"] != false || m["default"] != "egress-b" {
		t.Fatalf("json list = %v", m)
	}
	if profiles[1].(map[string]any)["default"] != true {
		t.Fatal("default flag")
	}
	h.writeFile("schema = \"relux-network-profiles-v1\"\nbogus = 1\n")
	code, stdout, stderr = h.run("list", "--json")
	wantDiag(t, stderr, "network_profile_invalid", "network.toml")
	if code != 1 || decode(t, stdout)["schema"] != "curator-network-error-v1" {
		t.Fatalf("invalid file: %d %q", code, stdout)
	}
}

func TestShow(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile(twoProfiles)
	code, stdout, stderr := h.run("show", "egress-zz")
	wantDiag(t, stderr, "network_profile_unknown", "egress-zz")
	if code != 1 || stdout != "" {
		t.Fatalf("unknown: %d %q", code, stdout)
	}
	code, stdout, _ = h.run("show", "egress-a")
	for _, want := range []string{"name:            egress-a", "endpoint:        http://127.0.0.1:18081", "bypass_hosts:    127.0.0.1, ::1, localhost", "probe_target:    probe.invalid:443", "digest:          sha256:1e5912de", "confirmed:       no\n", "default:         no", "unset: HTTP_PROXY HTTPS_PROXY ALL_PROXY FTP_PROXY NO_PROXY http_proxy https_proxy all_proxy ftp_proxy no_proxy", "set:   NO_PROXY=127.0.0.1,::1,localhost"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("show lacks %q:\n%s", want, stdout)
		}
	}
	if code != 0 {
		t.Fatal(code)
	}
	h.confirmAll()
	code, stdout, _ = h.run("show", "egress-b", "--json")
	m := decode(t, stdout)
	if code != 0 || m["schema"] != "curator-network-show-v1" || m["default"] != true {
		t.Fatalf("json show = %v", m)
	}
	conf := m["confirmation"].(map[string]any)
	if conf["confirmed"] != true || conf["confirmed_at"] != "2026-10-01T12:00:00Z" {
		t.Fatalf("confirmation = %v", conf)
	}
	patch := m["patch"].(map[string]any)
	if patch["adapter"] != "generic-env-v1" || len(patch["unset"].([]any)) != 10 || len(patch["set"].([]any)) != 6 {
		t.Fatalf("patch = %v", patch)
	}
	if set := patch["set"].([]any)[0].(map[string]any); set["name"] != "HTTP_PROXY" || set["value"] != "http://127.0.0.1:18082" {
		t.Fatalf("set[0] = %v", set)
	}
	// Content changed after confirmation: shown as unconfirmed at the new digest.
	h.writeFile(strings.Replace(twoProfiles, "18082", "18083", 1))
	_, stdout, _ = h.run("show", "egress-b")
	if !strings.Contains(stdout, "confirmed:       no (content changed since it was confirmed at sha256:") {
		t.Fatalf("changed content: %s", stdout)
	}
}

func TestAddAndRemove(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	code, stdout, stderr := h.run("add", "egress-a", "--endpoint", "HTTP://127.0.0.1:18081/", "--bypass", "Engine.Example, ,localhost", "--probe-target", "probe.invalid:443")
	if code != 0 || stderr != "" {
		t.Fatalf("add: %d %q %q", code, stdout, stderr)
	}
	if !strings.HasPrefix(stdout, "added egress-a (digest sha256:") || !strings.Contains(stdout, "pending confirmation: run `curator network confirm egress-a` from a terminal") {
		t.Fatalf("add output %q", stdout)
	}
	data, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml"))
	if err != nil || !strings.Contains(string(data), "bypass_hosts = [\"127.0.0.1\", \"::1\", \"engine.example\", \"localhost\"]") || !strings.Contains(string(data), "probe_target = \"probe.invalid:443\"") {
		t.Fatalf("file: %v\n%s", err, data)
	}
	code, stdout, _ = h.run("add", "egress-b", "--endpoint", "http://127.0.0.1:18082", "--json")
	m := decode(t, stdout)
	if code != 0 || m["schema"] != "curator-network-add-v1" || m["pending_confirmation"] != true || m["name"] != "egress-b" || m["profile"].(map[string]any)["endpoint"] != "http://127.0.0.1:18082" {
		t.Fatalf("json add = %v", m)
	}
	code, _, stderr = h.run("add", "egress-a", "--endpoint", "http://127.0.0.1:1")
	wantDiag(t, stderr, "network_configuration_conflict", "egress-a")
	if code != 1 {
		t.Fatal(code)
	}
	code, stdout, stderr = h.run("--json", "add", "egress-c", "--endpoint", "http://bob:hunter2@127.0.0.1:1")
	wantDiag(t, stderr, "network_profile_invalid", "egress-c")
	if code != 1 || strings.Contains(stderr+stdout, "hunter2") || strings.Contains(stderr+stdout, "bob") {
		t.Fatalf("secret leaked or wrong code: %d %q %q", code, stdout, stderr)
	}
	code, _, stderr = h.run("add", "Bad Name", "--endpoint", "http://127.0.0.1:1")
	if code != 1 || !strings.Contains(stderr, "network_profile_invalid") {
		t.Fatalf("bad name: %d %q", code, stderr)
	}
	h.confirmAll()
	code, stdout, _ = h.run("remove", "egress-a")
	if code != 0 || stdout != "removed egress-a (confirmation entry dropped)\n" {
		t.Fatalf("remove: %d %q", code, stdout)
	}
	l, err := confirm.Read(filepath.Join(h.home, ".curator", "network.confirmations.json"))
	if err != nil || len(l.Entries) != 1 {
		t.Fatalf("ledger after remove: %v %v", l, err)
	}
	code, stdout, _ = h.run("remove", "egress-b", "--json")
	m = decode(t, stdout)
	if code != 0 || m["schema"] != "curator-network-remove-v1" || m["removed"] != true || m["confirmation_dropped"] != true {
		t.Fatalf("json remove = %v", m)
	}
	code, _, stderr = h.run("remove", "egress-a")
	wantDiag(t, stderr, "network_profile_unknown", "egress-a")
	if code != 1 {
		t.Fatal(code)
	}
	if bak, err := os.ReadFile(filepath.Join(h.home, ".curator", "network.toml.bak")); err != nil || !strings.Contains(string(bak), "[networks.egress-b]") {
		t.Fatalf("backup: %v\n%s", err, bak)
	}
}

func TestCheckWithoutProbeNeverDials(t *testing.T) {
	t.Parallel()
	h := newHarness(t) // fatalProber
	code, stdout, _ := h.run("check")
	if code != 0 || stdout != "no network profiles in ~/.curator/network.toml\n" {
		t.Fatalf("empty check: %d %q", code, stdout)
	}
	h.writeFile(twoProfiles)
	code, stdout, stderr := h.run("check", "--all")
	if code != 0 || stderr != "" || stdout != "egress-a: valid (digest sha256:1e5912de9e34), confirmed: no\negress-b: valid (digest sha256:"+netprofile.ShortDigest(digestB(t))[7:]+"), confirmed: no\n" {
		t.Fatalf("check --all: %d %q %q", code, stdout, stderr)
	}
	code, stdout, _ = h.run("check", "egress-a", "--json")
	m := decode(t, stdout)
	results := m["results"].([]any)
	if code != 0 || m["schema"] != "curator-network-check-v1" || m["ok"] != true || m["probe"] != false || len(results) != 1 || results[0].(map[string]any)["probe"] != nil {
		t.Fatalf("json check = %v", m)
	}
	code, _, stderr = h.run("check", "egress-zz")
	wantDiag(t, stderr, "network_profile_unknown", "egress-zz")
	if code != 1 {
		t.Fatal(code)
	}
	h.writeFile("schema = \"relux-network-profiles-v1\"\n[networks.x]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\"]\n")
	code, _, stderr = h.run("check", "--all")
	wantDiag(t, stderr, "network_profile_invalid", "x")
	if code != 1 {
		t.Fatal(code)
	}
}

func digestB(t *testing.T) string {
	t.Helper()
	f, err := netprofile.Parse([]byte(twoProfiles))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := f.Lookup("egress-b")
	return netprofile.Digest(p)
}

func TestCheckProbe(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile(twoProfiles)
	fp := &fakeProber{fail: map[string]error{"http://127.0.0.1:18082": refusal.New(refusal.CodeProxyUnreachable, "egress-b", "tcp: connection refused")}}
	h.prober = fp
	code, stdout, stderr := h.run("check", "--all", "--probe", "--timeout", "250ms")
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stdout, "egress-a: probe http://127.0.0.1:18081: tcp ok, connect ok (200), tls ok, target probe.invalid:443\n") || !strings.Contains(stdout, "egress-b: probe http://127.0.0.1:18082: tcp failed, connect skipped, tls skipped — tcp: connection refused\n") {
		t.Fatalf("stdout:\n%s", stdout)
	}
	wantDiag(t, stderr, "network_proxy_unreachable", "egress-b")
	if len(fp.calls) != 2 || fp.calls[0].Target != "probe.invalid:443" || fp.calls[1].Target != "" || fp.calls[0].Timeout != 250*time.Millisecond {
		t.Fatalf("calls = %+v", fp.calls)
	}
	code, stdout, _ = h.run("check", "egress-b", "--probe", "--target", "Other.Invalid:8443", "--json")
	m := decode(t, stdout)
	r := m["results"].([]any)[0].(map[string]any)
	if code != 1 || m["ok"] != false || m["probe"] != true || r["ok"] != false || r["error"].(map[string]any)["code"] != "network_proxy_unreachable" || r["probe"].(map[string]any)["tcp"] != "failed" {
		t.Fatalf("json probe = %v", m)
	}
	if fp.calls[2].Target != "other.invalid:8443" {
		t.Fatalf("target override = %q", fp.calls[2].Target)
	}
	code, stdout, _ = h.run("check", "egress-a", "--probe", "--json")
	m = decode(t, stdout)
	if code != 0 || m["ok"] != true || m["results"].([]any)[0].(map[string]any)["probe"].(map[string]any)["tls"] != "ok" {
		t.Fatalf("json ok probe = %v", m)
	}
}

func TestConfirm(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.terminal = true
	h.stdin = "yes\n"
	saved := h.env
	h.env = append(append([]string{}, saved...), "CLAUDECODE=")
	code, _, stderr := h.run("confirm")
	wantDiag(t, stderr, "network_confirm_refused", "CLAUDECODE")
	if code != 1 {
		t.Fatal(code)
	}
	h.env = saved
	h.terminal = false
	code, stdout, stderr := h.run("confirm", "--json")
	wantDiag(t, stderr, "network_confirm_refused", "stdin")
	if code != 1 || decode(t, stdout)["schema"] != "curator-network-error-v1" {
		t.Fatalf("non-terminal: %d %q", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(h.home, ".curator", "network.confirmations.json")); !os.IsNotExist(err) {
		t.Fatal("ledger written by a refused confirm")
	}
	h.terminal = true
	h.stdin = "no\n"
	code, stdout, stderr = h.run("confirm", "egress-a")
	if code != 1 || !strings.Contains(stdout, "egress-a  http://127.0.0.1:18081  sha256:1e5912de") || !strings.Contains(stdout, "Type `yes` to confirm 1 profile(s): ") {
		t.Fatalf("declined: %d %q %q", code, stdout, stderr)
	}
	wantDiag(t, stderr, "network_confirm_refused", "operator")
	h.stdin = "yes\n"
	code, stdout, stderr = h.run("confirm", "egress-a")
	if code != 0 || stderr != "" || !strings.HasSuffix(stdout, "confirmed egress-a at sha256:1e5912de9e3459a12b7365f338d385c1c4c7b4a6b622598e17ed4004d7658699\n") {
		t.Fatalf("confirmed: %d %q %q", code, stdout, stderr)
	}
	l, err := confirm.Read(filepath.Join(h.home, ".curator", "network.confirmations.json"))
	if err != nil || !l.Confirmed("egress-a", "sha256:1e5912de9e3459a12b7365f338d385c1c4c7b4a6b622598e17ed4004d7658699") || len(l.Entries) != 1 {
		t.Fatalf("ledger: %v %v", l, err)
	}
	if e, _ := l.Entry("egress-a"); !e.ConfirmedAt.Equal(h.now) {
		t.Fatalf("confirmed_at = %v", e.ConfirmedAt)
	}
	h.stdin = "yes\n"
	code, stdout, stderr = h.run("confirm", "--json")
	m := decode(t, stdout)
	if code != 0 || m["schema"] != "curator-network-confirm-v1" || len(m["confirmed"].([]any)) != 1 || m["confirmed"].([]any)[0].(map[string]any)["name"] != "egress-b" || m["unchanged"].([]any)[0] != "egress-a" {
		t.Fatalf("json confirm = %v", m)
	}
	if !strings.Contains(stderr, "Type `yes`") {
		t.Fatal("json mode must prompt on stderr")
	}
	code, stdout, _ = h.run("confirm")
	if code != 0 || stdout != "nothing to confirm: 2 profile(s) already confirmed at their current digest\n" {
		t.Fatalf("nothing: %d %q", code, stdout)
	}
	code, _, stderr = h.run("confirm", "nope")
	wantDiag(t, stderr, "network_profile_unknown", "nope")
	if code != 1 {
		t.Fatal(code)
	}
	h.writeFile(strings.Replace(twoProfiles, "18081", "18089", 1))
	code, stdout, _ = h.run("confirm")
	if code != 0 || !strings.Contains(stdout, "(changed since sha256:1e5912de9e34)") || !strings.Contains(stdout, "confirmed egress-a at ") {
		t.Fatalf("re-confirm: %d %q", code, stdout)
	}
}

func TestExecDryRun(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.confirmAll()
	code, stdout, stderr := h.run("exec", "egress-a", "--dry-run", "--preflight-timeout", "1s", "--", "codex", "--full-auto")
	if code != 0 || stderr != "" {
		t.Fatalf("dry run: %d %q %q", code, stdout, stderr)
	}
	for _, want := range []string{"dry run: would exec codex (+1 args)", "profile_ref:      egress-a", "profile_digest:   sha256:1e5912de", "adapter=generic-env-v1 harness=exec build=\"\" entrypoint=codex", "assurance:        cooperative", "origin:           explicit", "probe:            tcp skipped, connect skipped, tls skipped at 2026-10-01T12:00:00Z", "set:   HTTPS_PROXY=http://127.0.0.1:18081"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("dry run lacks %q:\n%s", want, stdout)
		}
	}
	if len(h.exec.calls) != 0 {
		t.Fatal("dry run exec'd")
	}
	code, stdout, _ = h.run("--json", "exec", "--dry-run", "egress-b", "--", "/usr/local/bin/claude")
	m := decode(t, stdout)
	b := m["binding"].(map[string]any)
	if code != 0 || m["schema"] != "curator-network-exec-v1" || m["dry_run"] != true || b["profile_ref"] != "egress-b" || b["origin"] != "explicit" || b["adapter_identity"].(map[string]any)["entrypoint"] != "claude" || b["probe"].(map[string]any)["connect"] != "skipped" {
		t.Fatalf("json dry run = %v", m)
	}
	if _, leaks := b["env_patch"]; leaks {
		t.Fatal("record carries the env patch")
	}
	if m["patch"].(map[string]any)["set"].([]any)[0].(map[string]any)["value"] != "http://127.0.0.1:18082" || m["argc"] != float64(1) || m["entrypoint"] != "claude" {
		t.Fatalf("patch/command summary = %v", m)
	}
}

func TestExecAppliesPatchAndExecs(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.confirmAll()
	h.prober = &fakeProber{}
	tool := h.tool("agent")
	h.env = append(h.env, "HTTPS_PROXY=http://wrong.invalid:1", "http_proxy=http://wrong.invalid:1", "NO_PROXY=*", "all_proxy=socks5://wrong.invalid:1", "Http_Proxy=http://odd.invalid:1", "KEEP=1")
	code, stdout, stderr := h.run("exec", "egress-b", "--", "agent", "--flag", "value")
	if code != 0 || stdout != "" {
		t.Fatalf("exec: %d %q %q", code, stdout, stderr)
	}
	if !strings.HasPrefix(stderr, "curator-network: network=egress-b digest=sha256:") || !strings.Contains(stderr, "adapter=generic-env-v1 preflight=tcp ok, connect skipped, tls skipped") {
		t.Fatalf("stderr = %q", stderr)
	}
	if len(h.exec.calls) != 1 {
		t.Fatalf("exec calls = %d", len(h.exec.calls))
	}
	call := h.exec.calls[0]
	if call.path != tool || strings.Join(call.argv, " ") != "agent --flag value" {
		t.Fatalf("call = %+v", call)
	}
	env := strings.Join(call.env, "\n")
	for _, want := range []string{"HTTP_PROXY=http://127.0.0.1:18082", "HTTPS_PROXY=http://127.0.0.1:18082", "http_proxy=http://127.0.0.1:18082", "https_proxy=http://127.0.0.1:18082", "NO_PROXY=127.0.0.1,::1,localhost", "no_proxy=127.0.0.1,::1,localhost", "KEEP=1", "HOME=" + h.home} {
		if !strings.Contains(env+"\n", want+"\n") {
			t.Errorf("child env lacks %s:\n%s", want, env)
		}
	}
	for _, bad := range []string{"wrong.invalid", "odd.invalid", "NO_PROXY=*", "all_proxy", "Http_Proxy"} {
		if strings.Contains(env, bad) {
			t.Errorf("child env carries %s:\n%s", bad, env)
		}
	}
	for _, name := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "NO_PROXY="} {
		if strings.Count(env+"\n", "\n"+name) != 1 {
			t.Errorf("%s appears %d times", name, strings.Count(env+"\n", "\n"+name))
		}
	}
	if strings.Contains(strings.Join(h.env, "\n"), "127.0.0.1:18082") {
		t.Fatal("the parent environment was changed")
	}
}

func TestExecRefusesBeforeExec(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile(twoProfiles)
	h.tool("agent")
	fp := &fakeProber{fail: map[string]error{"http://127.0.0.1:18081": refusal.New(refusal.CodeProxyUnreachable, "egress-a", "tcp: connection refused")}}
	h.prober = fp
	cases := []struct {
		name    string
		prep    func()
		args    []string
		code    int
		diag    string
		subject string
	}{
		{"unknown profile", nil, []string{"exec", "egress-zz", "--", "agent"}, 1, "network_profile_unknown", "egress-zz"},
		{"unconfirmed profile", nil, []string{"exec", "egress-b", "--", "agent"}, 1, "network_profile_denied", "egress-b"},
		{"unreachable proxy", h.confirmAll, []string{"exec", "egress-a", "--", "agent"}, 1, "network_proxy_unreachable", "egress-a"},
		{"command not found", nil, []string{"exec", "egress-b", "--", "missing-tool"}, 2, "usage", "exec"},
		{"no separator", nil, []string{"exec", "egress-b", "agent"}, 2, "usage", "exec"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prep != nil {
				tc.prep()
			}
			before := len(h.exec.calls)
			code, _, stderr := h.run(tc.args...)
			if code != tc.code || !strings.HasPrefix(stderr, "curator-network: "+tc.diag+": "+tc.subject) {
				t.Fatalf("%v: code %d, stderr %q", tc.args, code, stderr)
			}
			if len(h.exec.calls) != before {
				t.Fatal("exec was called despite the refusal")
			}
		})
	}
	h.exec.err = errors.New("permission denied")
	fp.fail = nil
	code, _, stderr := h.run("exec", "egress-b", "--", "agent")
	if code != 2 || !strings.Contains(stderr, "cannot execute command") {
		t.Fatalf("exec failure: %d %q", code, stderr)
	}
	code, stdout, stderr := h.run("--json", "exec", "egress-zz", "--", "agent")
	if code != 1 || decode(t, stdout)["error"].(map[string]any)["subject"] != "egress-zz" {
		t.Fatalf("json refusal: %d %q %q", code, stdout, stderr)
	}
}

func TestNoHome(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.env = []string{"PATH=/bin"}
	for _, args := range [][]string{{"list"}, {"show", "a"}, {"add", "a", "--endpoint", "http://127.0.0.1:1"}, {"remove", "a"}, {"check"}, {"exec", "a", "--", "x"}} {
		code, _, stderr := h.run(args...)
		if code != 1 || !strings.HasPrefix(stderr, "curator-network: network_file_unreadable: network.toml: HOME is not set") {
			t.Errorf("%v: %d %q", args, code, stderr)
		}
	}
}
