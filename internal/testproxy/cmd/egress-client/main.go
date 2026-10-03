// SPDX-License-Identifier: Apache-2.0

// Command egress-client is the test and demo client of the exec
// milestone: it performs GET http://egress.invalid/ through the proxy
// configured in its own environment (http.ProxyFromEnvironment) and
// prints the body. It never dials directly: with no proxy configured for
// the URL it exits 3 without resolving the name. --marker creates a file
// first, so a test can prove whether the client ran at all. --dump-proxy-env
// prints only proxy-family variables and exits without any network call.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("egress-client", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dump := fs.Bool("dump-proxy-env", false, "print proxy-family variables as JSON and exit without dialing")
	marker := fs.String("marker", "", "create this file before doing anything else")
	target := fs.String("url", "http://egress.invalid/", "URL to fetch through the environment's proxy")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *marker != "" {
		if err := os.WriteFile(*marker, []byte("egress-client ran\n"), 0o600); err != nil {
			fmt.Fprintf(stderr, "egress-client: marker: %v\n", err)
			return 1
		}
	}
	if *dump {
		return dumpProxyEnv(os.Environ(), stdout)
	}
	u, err := url.Parse(*target)
	if err != nil {
		fmt.Fprintf(stderr, "egress-client: url: %v\n", err)
		return 2
	}
	proxy, err := http.ProxyFromEnvironment(&http.Request{URL: u})
	if err != nil {
		fmt.Fprintf(stderr, "egress-client: proxy: %v\n", err)
		return 1
	}
	if proxy == nil {
		fmt.Fprintf(stderr, "egress-client: no proxy configured for %s; refusing to dial directly\n", u.Host)
		return 3
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *target, nil)
	if err != nil {
		fmt.Fprintf(stderr, "egress-client: %v\n", err)
		return 1
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "egress-client: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(stderr, "egress-client: read: %v\n", err)
		return 1
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "egress-client: status %d: %s\n", resp.StatusCode, body)
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

// dumpProxyEnv returns only the reserved proxy family, without dialing.
func dumpProxyEnv(env []string, stdout io.Writer) int {
	entries := []string{}
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY":
			entries = append(entries, entry)
		}
	}
	sort.Strings(entries)
	if err := json.NewEncoder(stdout).Encode(entries); err != nil {
		return 1
	}
	return 0
}
