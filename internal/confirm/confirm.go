// SPDX-License-Identifier: Apache-2.0

// Package confirm keeps the confirmation ledger
// `$HOME/.curator/network.confirmations.json` (schema
// relux-network-confirmations-v1) and the agent-session guardrail of
// `curator network confirm`.
//
// TODO(decision): the ledger stands in for curator-trust §10 presence-key
// signing, which does not exist yet. A profile is confirmed at one digest;
// any content change needs re-confirmation (trust §10 would let a
// narrowing edit apply at once; not implemented).
package confirm

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/atomicfile"
	"github.com/relux-works/curator-network-profiles/internal/envutil"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// Schema is the ledger's schema id.
const Schema = "relux-network-confirmations-v1"

// Markers are the environment variables whose set-ness (not value)
// identifies an agent session; confirm refuses under any of them.
var Markers = []string{
	"CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT",
	"CODEX_THREAD_ID", "CODEX_SESSION", "CODEX_CI",
	"TASK_BOARD_RUN_ID", "A2A_AGENT",
}

// Entry is one confirmed profile.
type Entry struct {
	Digest      string    `json:"digest"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

// Ledger maps profile names to their confirmed digest.
type Ledger struct {
	Schema  string           `json:"schema"`
	Entries map[string]Entry `json:"confirmed"`
}

// Empty returns a ledger with no entries.
func Empty() *Ledger { return &Ledger{Schema: Schema, Entries: map[string]Entry{}} }

// Read loads the ledger at path. An absent file is an empty ledger; an
// unreadable or malformed one is network_file_unreadable (the subject is
// the basename); a foreign schema is refused the same way.
func Read(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Empty(), nil
	}
	name := filepath.Base(path)
	if err != nil {
		return nil, refusal.New(refusal.CodeFileUnreadable, name, "cannot read")
	}
	var l Ledger
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, refusal.New(refusal.CodeFileUnreadable, name, "cannot parse")
	}
	if l.Schema != Schema {
		return nil, refusal.New(refusal.CodeFileUnreadable, name, "unexpected schema; expected "+Schema)
	}
	if l.Entries == nil {
		l.Entries = map[string]Entry{}
	}
	return &l, nil
}

// Write stores the ledger atomically with mode 0600.
func Write(path string, l *Ledger) error {
	if l.Schema == "" {
		l.Schema = Schema
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return refusal.New(refusal.CodeFileUnreadable, filepath.Base(path), "cannot encode")
	}
	if err := atomicfile.Write(path, append(data, '\n')); err != nil {
		return refusal.New(refusal.CodeFileUnreadable, filepath.Base(path), "cannot write")
	}
	return nil
}

// Confirmed reports whether name is confirmed at exactly digest.
func (l *Ledger) Confirmed(name, digest string) bool {
	if l == nil || digest == "" {
		return false
	}
	e, ok := l.Entries[name]
	return ok && e.Digest == digest
}

// Entry returns the ledger entry of name.
func (l *Ledger) Entry(name string) (Entry, bool) {
	if l == nil {
		return Entry{}, false
	}
	e, ok := l.Entries[name]
	return e, ok
}

// Set records name as confirmed at digest.
func (l *Ledger) Set(name, digest string, at time.Time) {
	if l.Entries == nil {
		l.Entries = map[string]Entry{}
	}
	l.Entries[name] = Entry{Digest: digest, ConfirmedAt: at.UTC()}
}

// Delete drops name; it reports whether an entry existed.
func (l *Ledger) Delete(name string) bool {
	if l == nil || l.Entries == nil {
		return false
	}
	_, ok := l.Entries[name]
	delete(l.Entries, name)
	return ok
}

// Names returns the confirmed names in byte order.
func (l *Ledger) Names() []string {
	if l == nil {
		return nil
	}
	names := make([]string, 0, len(l.Entries))
	for n := range l.Entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Guard refuses confirmation inside an agent session (any marker set in
// env, whatever its value) or without a terminal on stdin.
func Guard(env []string, isTerminal bool) error {
	for _, m := range Markers {
		if envutil.Has(env, m) {
			return refusal.New(refusal.CodeConfirmRefused, m, "agent session marker is set; run `curator network confirm` from an operator terminal")
		}
	}
	if !isTerminal {
		return refusal.New(refusal.CodeConfirmRefused, "stdin", "not a terminal; run `curator network confirm` from an operator terminal")
	}
	return nil
}
