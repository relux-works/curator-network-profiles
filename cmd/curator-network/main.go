// SPDX-License-Identifier: Apache-2.0

// Command curator-network is the Curator provider behind
// `curator network <verb> …`. main is thin: it builds the process
// boundaries and hands argv[1:] to internal/cli.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/cli"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	deps := cli.Deps{
		Env:    os.Environ(),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		IsTerminal: func() bool {
			fi, err := os.Stdin.Stat()
			return err == nil && fi.Mode()&os.ModeCharDevice != 0
		},
		Exec:   execve,
		Prober: &probe.Dialer{},
		Now:    time.Now,
	}
	code := cli.Run(ctx, os.Args[1:], deps)
	stop()
	os.Exit(code)
}
