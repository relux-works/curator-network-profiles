// SPDX-License-Identifier: Apache-2.0

package main_test

// The N-A milestone test: two launches of the built provider use two
// loopback egresses at the same time, with hostile ambient proxy
// variables in the parent, and refusals happen before the child runs.
//
// Everything is loopback: three in-process proxies on 127.0.0.1, a
// temporary HOME, no DNS name resolved (the client asks the proxy for
// http://egress.invalid/ and the proxy answers itself). The
// confirmation ledger is seeded as a FIXTURE: `curator network confirm`
// refuses inside an agent session or without a terminal by design, so
// the fixture stands in for the operator's confirmation.

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/internal/testproxy"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
)

var binDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "curator-network-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binDir = dir
	// Read the parent's warm cache locations once with GOENV=off, so even
	// this query cannot read an operator Go env file. Builds then pin both
	// caches explicitly and use a private HOME/XDG and offline, scrubbed env.
	query := exec.Command("go", "env", "GOCACHE", "GOMODCACHE")
	query.Env = offlineEnv(os.Environ())
	cacheOutput, err := query.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "go env cache directories:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	caches := strings.Split(strings.TrimSpace(string(cacheOutput)), "\n")
	if len(caches) != 2 {
		fmt.Fprintln(os.Stderr, "go env returned invalid cache directories")
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Join(dir, "home"), 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	buildEnvironment := buildEnv(os.Environ(), filepath.Join(dir, "home"), caches[0], caches[1])
	for _, b := range []struct{ name, pkg string }{{"curator-network", "."}, {"egress-client", "../../internal/testproxy/cmd/egress-client"}} {
		cmd := exec.Command("go", "build", "-p", "1", "-o", filepath.Join(dir, b.name), b.pkg)
		cmd.Env = buildEnvironment
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", b.name, err, out)
			_ = os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type fixture struct {
	home  string
	env   []string
	a, b  *testproxy.Proxy
	wrong *testproxy.Proxy
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{home: t.TempDir()}
	for _, p := range []struct {
		id  string
		dst **testproxy.Proxy
	}{{"A", &f.a}, {"B", &f.b}, {"WRONG", &f.wrong}} {
		px, err := testproxy.Start(testproxy.Options{ID: p.id})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = px.Close() })
		*p.dst = px
	}
	base := []string{"HOME=" + f.home, "PATH=" + binDir, "XDG_CONFIG_HOME=" + filepath.Join(f.home, "config"), "XDG_CACHE_HOME=" + filepath.Join(f.home, "cache"), "XDG_DATA_HOME=" + filepath.Join(f.home, "data"), "TMPDIR=" + f.home}
	for _, add := range []struct{ name, url string }{{"egress-a", f.a.URL()}, {"egress-b", f.b.URL()}} {
		cmd := exec.Command(filepath.Join(binDir, "curator-network"), "add", add.name, "--endpoint", add.url)
		cmd.Env = base
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("add %s: %v\n%s", add.name, err, out)
		}
	}
	addDirect := exec.Command(filepath.Join(binDir, "curator-network"), "add", "direct", "--direct")
	addDirect.Env = base
	if out, err := addDirect.CombinedOutput(); err != nil {
		t.Fatalf("add direct: %v\n%s", err, out)
	}
	// A profile whose proxy is not listening, for the refusal case.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + closed.Addr().String()
	_ = closed.Close()
	cmd := exec.Command(filepath.Join(binDir, "curator-network"), "add", "egress-dead", "--endpoint", dead)
	cmd.Env = base
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add egress-dead: %v\n%s", err, out)
	}
	// FIXTURE: confirm every profile at its current digest.
	data, err := os.ReadFile(filepath.Join(f.home, ".curator", "network.toml"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := netprofile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	ledger := confirm.Empty()
	for _, name := range file.Names() {
		p, _ := file.Lookup(name)
		ledger.Set(name, netprofile.Digest(p), time.Now())
	}
	if err := confirm.Write(filepath.Join(f.home, ".curator", "network.confirmations.json"), ledger); err != nil {
		t.Fatal(err)
	}
	// Hostile ambient values in the parent of every launch.
	f.env = append(base,
		"HTTPS_PROXY="+f.wrong.URL(), "http_proxy="+f.wrong.URL(), "all_proxy="+f.wrong.URL(),
		"NO_PROXY=*", "Http_Proxy="+f.wrong.URL())
	return f
}

type launch struct {
	stdout, stderr string
	code           int
	err            error
}

func (f *fixture) launchRaw(args ...string) launch {
	cmd := exec.Command(filepath.Join(binDir, "curator-network"), args...)
	cmd.Env = f.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errorsAs(err, &ee) {
			return launch{stdout: stdout.String(), stderr: stderr.String(), code: -1, err: err}
		}
		code = ee.ExitCode()
	}
	return launch{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func (f *fixture) launch(t *testing.T, args ...string) launch {
	t.Helper()
	result := f.launchRaw(args...)
	if result.err != nil {
		t.Fatalf("run command: %v", result.err)
	}
	return result
}

func errorsAs(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

func TestTwoEgressesAndDirectConcurrently(t *testing.T) {
	f := newFixture(t)
	// Each worker sends both process results and startup errors; only this
	// test goroutine invokes the testing API.
	aResults, bResults, directResults := make(chan launch, 1), make(chan launch, 1), make(chan launch, 1)
	go func() { aResults <- f.launchRaw("exec", "egress-a", "--", "egress-client") }()
	go func() { bResults <- f.launchRaw("exec", "egress-b", "--", "egress-client") }()
	go func() {
		directResults <- f.launchRaw("--json", "exec", "direct", "--", "egress-client", "--dump-proxy-env")
	}()
	la, lb, ld := <-aResults, <-bResults, <-directResults
	for _, result := range []launch{la, lb, ld} {
		if result.err != nil {
			t.Fatalf("launch startup: %v", result.err)
		}
	}
	if la.code != 0 || la.stdout != "egress=A\n" {
		t.Errorf("launch A: code %d stdout %q stderr %q", la.code, la.stdout, la.stderr)
	}
	if lb.code != 0 || lb.stdout != "egress=B\n" {
		t.Errorf("launch B: code %d stdout %q stderr %q", lb.code, lb.stdout, lb.stderr)
	}
	for _, l := range []launch{la, lb} {
		if !strings.HasPrefix(l.stderr, "curator-network: network=egress-") || !strings.Contains(l.stderr, "preflight=tcp ok, connect skipped, tls skipped") {
			t.Errorf("launch stderr %q", l.stderr)
		}
	}
	if ld.code != 0 || ld.stdout != "[]\n" || !strings.Contains(ld.stderr, "network=direct") || !strings.Contains(ld.stderr, "preflight=tcp skipped, connect skipped, tls skipped") {
		t.Errorf("direct: code %d stdout %q stderr %q", ld.code, ld.stdout, ld.stderr)
	}
	want := []testproxy.Request{{Method: "GET", Target: "http://egress.invalid/"}}
	if got := f.a.Requests(); !reflect.DeepEqual(got, want) {
		t.Errorf("proxy A saw %+v", got)
	}
	if got := f.b.Requests(); !reflect.DeepEqual(got, want) {
		t.Errorf("proxy B saw %+v", got)
	}
	if got := f.wrong.Requests(); len(got) != 0 {
		t.Errorf("the ambient proxy saw %+v", got)
	}
}

func TestRefusalsHappenBeforeTheChildRuns(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name    string
		profile string
		code    string
	}{
		{"unknown profile", "egress-zz", "network_profile_unknown"},
		{"unreachable proxy", "egress-dead", "network_proxy_unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(f.home, tc.profile+".marker")
			l := f.launch(t, "exec", tc.profile, "--preflight-timeout", "500ms", "--", "egress-client", "--marker", marker)
			if l.code != 1 || !strings.HasPrefix(l.stderr, "curator-network: "+tc.code+": "+tc.profile+": ") || l.stdout != "" {
				t.Fatalf("code %d stdout %q stderr %q", l.code, l.stdout, l.stderr)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("the child ran: marker exists")
			}
		})
	}
	if got := f.wrong.Requests(); len(got) != 0 {
		t.Errorf("the ambient proxy saw %+v", got)
	}
	// The client itself never dials directly: without a proxy it exits 3.
	cmd := exec.Command(filepath.Join(binDir, "egress-client"))
	cmd.Env = []string{"HOME=" + f.home, "PATH=" + binDir}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errorsAs(err, &ee) || ee.ExitCode() != 3 || !strings.Contains(string(out), "refusing to dial directly") {
		t.Fatalf("egress-client without a proxy: %v %s", err, out)
	}
}

func TestDryRunAndJSONThroughTheBinary(t *testing.T) {
	f := newFixture(t)
	l := f.launch(t, "--json", "exec", "egress-a", "--dry-run", "--", "egress-client")
	if l.code != 0 || !strings.Contains(l.stdout, `"schema":"curator-network-exec-v1"`) || !strings.Contains(l.stdout, `"profile_ref":"egress-a"`) {
		t.Fatalf("dry run: code %d stdout %q stderr %q", l.code, l.stdout, l.stderr)
	}
	if got := f.a.Requests(); len(got) != 0 {
		t.Fatalf("dry run reached the proxy: %+v", got)
	}
	// A TCP-only dry run must also succeed when the proxy is unreachable.
	l = f.launch(t, "exec", "egress-dead", "--dry-run", "--json", "--", "egress-client")
	if l.code != 0 || !strings.Contains(l.stdout, `"tcp":"skipped","connect":"skipped","tls":"skipped"`) {
		t.Fatalf("unreachable dry run: %+v", l)
	}
	l = f.launch(t, "check", "--all", "--probe", "--json")
	if l.code != 1 || !strings.Contains(l.stdout, `"schema":"curator-network-check-v1","ok":false`) || !strings.Contains(l.stderr, "network_proxy_unreachable: egress-dead") {
		t.Fatalf("check: code %d stdout %q stderr %q", l.code, l.stdout, l.stderr)
	}
	l = f.launch(t, "list")
	if l.code != 0 || !strings.Contains(l.stdout, "egress-a") || !strings.Contains(l.stdout, "yes") {
		t.Fatalf("list: %q", l.stdout)
	}
}

// offlineEnv also protects the cache-location query from fetching. Private
// module routing and checksum settings cannot bypass GOPROXY=off.
func offlineEnv(parent []string) []string {
	out := make([]string, 0, len(parent))
	for _, entry := range parent {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || strings.HasSuffix(strings.ToLower(name), "_proxy") || name == "GOPROXY" || name == "GOFLAGS" || name == "GOTOOLCHAIN" || name == "GOPRIVATE" || name == "GONOPROXY" || name == "GOSUMDB" || name == "GOENV" {
			continue
		}
		out = append(out, entry)
	}
	return append(out, "GOPROXY=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local", "GONOPROXY=none", "GOPRIVATE=none", "GOSUMDB=off", "GOENV=off")
}

func buildEnv(parent []string, home, cache, modcache string) []string {
	out := make([]string, 0, len(parent))
	for _, entry := range offlineEnv(parent) {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOENV":
			continue
		}
		out = append(out, entry)
	}
	return append(out, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "config"), "XDG_CACHE_HOME="+filepath.Join(home, "cache"), "XDG_DATA_HOME="+filepath.Join(home, "data"), "TMPDIR="+home, "GOCACHE="+cache, "GOMODCACHE="+modcache, "GOENV=off")
}

func TestBuildEnvironmentIsOfflineAndPrivate(t *testing.T) {
	t.Parallel()
	parent := []string{"PATH=/tools", "HOME=/operator", "XDG_CONFIG_HOME=/operator-config", "HTTPS_PROXY=http://ambient.invalid:1", "weird_proxy=http://ambient.invalid:1", "Http_Proxy=http://ambient.invalid:1", "GOPROXY=https://ambient.invalid", "GOPRIVATE=*.invalid", "GONOPROXY=*", "GOSUMDB=ambient.invalid", "GOFLAGS=-mod=mod", "GOCACHE=/old-cache", "GOMODCACHE=/old-modcache", "KEEP=ok"}
	before := append([]string(nil), parent...)
	home := t.TempDir()
	got := buildEnv(parent, home, "/warm-cache", "/warm-modcache")
	values := map[string]string{}
	for _, entry := range got {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if strings.HasSuffix(strings.ToLower(name), "_proxy") {
			t.Errorf("ambient proxy retained: %s", name)
		}
		if _, duplicate := values[name]; duplicate {
			t.Errorf("duplicate %s", name)
		}
		values[name] = value
	}
	for key, want := range map[string]string{"HOME": home, "GOCACHE": "/warm-cache", "GOMODCACHE": "/warm-modcache", "GOPROXY": "off", "GONOPROXY": "none", "GOPRIVATE": "none", "GOSUMDB": "off", "GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local", "GOENV": "off", "PATH": "/tools", "KEEP": "ok"} {
		if values[key] != want {
			t.Errorf("%s = %q, want %q", key, values[key], want)
		}
	}
	for _, key := range []string{"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR"} {
		if !strings.HasPrefix(values[key], home+string(filepath.Separator)) && !(key == "TMPDIR" && values[key] == home) {
			t.Errorf("%s outside temp HOME", key)
		}
	}
	if !reflect.DeepEqual(parent, before) {
		t.Fatal("parent env mutated")
	}
}

func TestCacheQueryDisablesOperatorGoEnvironment(t *testing.T) {
	env := offlineEnv([]string{"HOME=/operator", "GOENV=/operator/go/env"})
	var values []string
	for _, entry := range env {
		if strings.HasPrefix(entry, "GOENV=") {
			values = append(values, entry)
		}
	}
	if !reflect.DeepEqual(values, []string{"GOENV=off"}) {
		t.Fatalf("cache query Go environment = %v, want GOENV=off", values)
	}
}
