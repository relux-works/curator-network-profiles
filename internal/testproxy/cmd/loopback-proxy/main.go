// SPDX-License-Identifier: Apache-2.0

// Command loopback-proxy runs internal/testproxy as a process for the
// demo: it binds 127.0.0.1:0 (or --listen on loopback), prints its URL on
// stdout (and into --addr-file when given), logs every request to
// stderr, and stops on SIGINT/SIGTERM.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/relux-works/curator-network-profiles/internal/testproxy"
)

type targetFlags map[string]string

func (t targetFlags) String() string { return fmt.Sprint(map[string]string(t)) }

func (t targetFlags) Set(v string) error {
	key, addr, ok := strings.Cut(v, "=")
	if !ok || key == "" || addr == "" {
		return fmt.Errorf("--target wants authority=loopback-addr, got %q", v)
	}
	t[key] = addr
	return nil
}

func main() {
	fs := flag.NewFlagSet("loopback-proxy", flag.ContinueOnError)
	id := fs.String("id", "A", "proxy id echoed as egress=<id>")
	listen := fs.String("listen", "127.0.0.1:0", "loopback bind address")
	addrFile := fs.String("addr-file", "", "write the proxy URL into this file (atomically) once bound")
	requireAuth := fs.Bool("require-auth", false, "answer 407 without Proxy-Authorization")
	targets := targetFlags{}
	fs.Var(targets, "target", "CONNECT authority=loopback address (repeatable)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	p, err := testproxy.Start(testproxy.Options{
		ID: *id, Listen: *listen, Targets: targets, RequireAuth: *requireAuth,
		Logf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) },
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "loopback-proxy: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(p.URL())
	if *addrFile != "" {
		tmp := filepath.Join(filepath.Dir(*addrFile), "."+filepath.Base(*addrFile)+".tmp")
		if err := os.WriteFile(tmp, []byte(p.URL()+"\n"), 0o600); err == nil {
			err = os.Rename(tmp, *addrFile)
		} else {
			fmt.Fprintf(os.Stderr, "loopback-proxy: addr-file: %v\n", err)
			os.Exit(1)
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = p.Close()
}
