// SPDX-License-Identifier: Apache-2.0

// Package catalog is the read-only entry point for process owners
// (curator-run, task-board, session hosts): it loads the operator catalog
// and the confirmation ledger from an injected environment and answers
// the Confirmations interface of pkg/resolve. It writes nothing; edits
// belong to the provider CLI.
//
// TODO(decision): the brief keeps file plumbing under internal/; this
// thin public facade exists so a caller in another module never has to
// re-implement the paths, the read refusals or the ledger format.
package catalog

import (
	"time"

	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

// Catalog is a loaded machine catalog. File is nil when the machine has
// no `~/.curator/network.toml`.
type Catalog struct {
	File   *netprofile.File
	ledger *confirm.Ledger
}

// Load reads the catalog and the ledger located through HOME in env.
// Every failure is a *refusal.Refusal: an unset HOME, a file that exists
// but cannot be read or parsed, an invalid profile, a broken ledger. An
// absent catalog is not a failure.
func Load(env []string) (*Catalog, error) {
	paths, err := store.PathsFromEnv(env)
	if err != nil {
		return nil, err
	}
	file, _, err := store.Read(paths)
	if err != nil {
		return nil, err
	}
	ledger, err := confirm.Read(paths.Ledger)
	if err != nil {
		return nil, err
	}
	return &Catalog{File: file, ledger: ledger}, nil
}

// Confirmed implements resolve.Confirmations.
func (c *Catalog) Confirmed(name, digest string) bool {
	if c == nil {
		return false
	}
	return c.ledger.Confirmed(name, digest)
}

// ConfirmedAt returns the digest a profile was confirmed at and when.
func (c *Catalog) ConfirmedAt(name string) (digest string, at time.Time, ok bool) {
	if c == nil {
		return "", time.Time{}, false
	}
	e, ok := c.ledger.Entry(name)
	return e.Digest, e.ConfirmedAt, ok
}

// Resolve applies resolve.Resolve to this host's catalog, including fresh
// resolution of a caller-supplied inherited reference. Load never derives
// an inherited reference from the supplied environment.
func (c *Catalog) Resolve(req resolve.Request) (*resolve.Result, error) {
	if c == nil {
		return resolve.Resolve(nil, resolve.None, req)
	}
	return resolve.Resolve(c.File, c, req)
}
