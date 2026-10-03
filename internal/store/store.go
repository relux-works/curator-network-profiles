// SPDX-License-Identifier: Apache-2.0

// Package store is the file plumbing of the operator catalog
// `$HOME/.curator/network.toml`: paths from an injected environment,
// reading, comment-preserving text edits for `add` and `remove`, and the
// atomic write with one backup. HOME comes from the injected environment
// only; nothing here reads os.Getenv.
package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/relux-works/curator-network-profiles/internal/atomicfile"
	"github.com/relux-works/curator-network-profiles/internal/envutil"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

const (
	// DirName is the Curator namespace under HOME.
	DirName = ".curator"
	// BackupName keeps the previous catalog bytes after an edit.
	BackupName = "network.toml.bak"
	// LedgerName is the confirmation ledger beside the catalog.
	LedgerName = "network.confirmations.json"
)

// Paths locate the operator files.
type Paths struct {
	Dir    string
	File   string
	Backup string
	Ledger string
}

// PathsFromEnv derives the paths from HOME in env. An unset or empty
// HOME is network_file_unreadable: the catalog cannot be located.
func PathsFromEnv(env []string) (Paths, error) {
	home, ok := envutil.Lookup(env, "HOME")
	if !ok || strings.TrimSpace(home) == "" {
		return Paths{}, refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "HOME is not set; the catalog cannot be located")
	}
	dir := filepath.Join(home, DirName)
	return Paths{
		Dir:    dir,
		File:   filepath.Join(dir, netprofile.FileName),
		Backup: filepath.Join(dir, BackupName),
		Ledger: filepath.Join(dir, LedgerName),
	}, nil
}

// Read loads and parses the catalog. An absent file yields (nil, nil,
// nil): no profiles. A file that exists but cannot be read is
// network_file_unreadable; parse and validation refusals come from
// netprofile.Parse. The raw bytes are returned for text edits.
func Read(p Paths) (*netprofile.File, []byte, error) {
	data, err := os.ReadFile(p.File)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		detail := "cannot read"
		if errors.Is(err, fs.ErrPermission) {
			detail = "cannot read: permission denied"
		}
		return nil, nil, refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, detail)
	}
	f, err := netprofile.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return f, data, nil
}

// Add appends a `[networks.<name>]` block for the normalized profile,
// keeping every other byte of the file. The result is parsed and
// validated before it is written; the previous bytes go to the backup.
// An existing name is refused (no silent overwrite).
func Add(p Paths, prof netprofile.Profile) error {
	return Edit(p, func(e *Editor) error { return e.Add(prof) })
}

// Editor performs catalog edits while Edit holds the advisory lock.
// It must only be used inside the callback and never concurrently.
type Editor struct{ paths Paths }

// Edit holds network.toml.lock across a catalog read/edit/write and any
// related ledger operations in the callback. It refuses symlinked catalogs
// before invoking the callback; use WithCatalogLock for read-only catalog access.
func Edit(p Paths, fn func(*Editor) error) error {
	return WithCatalogLock(p, func() error {
		info, err := os.Lstat(p.File)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "cannot inspect catalog")
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "cannot edit a symlink catalog; edit its target explicitly")
		}
		return fn(&Editor{paths: p})
	})
}

// WithCatalogLock holds network.toml.lock across the callback, without
// inspecting or mutating the catalog. Read-only catalog access may follow
// symlinks while serializing related ledger writes with Edit. Contention
// refuses immediately; a stale lock is never removed automatically. Cleanup
// runs on every return. The callback must not acquire the same lock again.
func WithCatalogLock(p Paths, fn func() error) error {
	if err := atomicfile.EnsureDir(p.Dir); err != nil {
		return refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "cannot create catalog directory")
	}
	lockPath := p.File + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return refusal.New(refusal.CodeConfigurationConflict, netprofile.FileName, "catalog edit is locked; retry after the other edit finishes")
	}
	if err != nil {
		return refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "cannot create edit lock")
	}
	defer os.Remove(lockPath)
	if err := lock.Close(); err != nil {
		return refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "cannot close edit lock")
	}
	return fn()
}

// Add appends a profile under the lock held by Edit.
func (e *Editor) Add(prof netprofile.Profile) error {
	p := e.paths
	existing, data, err := Read(p)
	if err != nil {
		return err
	}
	if _, dup := existing.Lookup(prof.Name); dup {
		// TODO(decision): the brief says "refuse an existing name"; the
		// closed set has no "exists" code, conflict is the closest.
		return refusal.New(refusal.CodeConfigurationConflict, prof.Name, "profile already exists; remove it first")
	}
	var out []byte
	if data == nil {
		out = []byte("schema = " + strconv.Quote(netprofile.Schema) + "\n")
	} else {
		out = append(out, data...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
	}
	out = append(out, '\n')
	out = append(out, renderBlock(prof)...)
	parsed, err := netprofile.Parse(out)
	if err != nil {
		return err
	}
	got, ok := parsed.Lookup(prof.Name)
	if !ok || netprofile.Digest(got) != netprofile.Digest(prof) {
		return refusal.New(refusal.CodeProfileInvalid, prof.Name, "the edited file does not round-trip the new profile")
	}
	return write(p, out, data != nil)
}

// Remove deletes the table's contiguous leading comments, header and body
// through its last non-blank, non-comment line. Trailing comments and blank
// lines before the next header or EOF are preserved byte for byte. A
// profile defined in another TOML form is refused rather than guessed
// at; the operator default cannot be removed while `default` names it.
func Remove(p Paths, name string) error {
	if _, err := os.Lstat(p.File); errors.Is(err, fs.ErrNotExist) {
		return refusal.New(refusal.CodeProfileUnknown, name, "no such network profile on this machine")
	}
	return Edit(p, func(e *Editor) error { return e.Remove(name) })
}

// Remove deletes a profile under the lock held by Edit.
func (e *Editor) Remove(name string) error {
	p := e.paths
	existing, data, err := Read(p)
	if err != nil {
		return err
	}
	if _, ok := existing.Lookup(name); !ok {
		return refusal.New(refusal.CodeProfileUnknown, name, "no such network profile on this machine")
	}
	if existing.Default == name {
		return refusal.New(refusal.CodeConfigurationConflict, name, "profile is the operator default; change `default` first")
	}
	lines := splitLines(data)
	header := headerPattern(name)
	start := -1
	for i, line := range lines {
		if header.MatchString(strings.TrimSuffix(line, "\n")) {
			start = i
			break
		}
	}
	if start < 0 {
		return refusal.New(refusal.CodeProfileInvalid, name, "profile is not defined as a [networks.<name>] table; edit the file by hand")
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if anyHeader.MatchString(lines[i]) {
			end = i
			break
		}
	}
	// Keep the next table's leading comments and all trailing spacing.
	for end > start+1 {
		line := strings.TrimSpace(lines[end-1])
		if line != "" && !strings.HasPrefix(line, "#") {
			break
		}
		end--
	}
	// Only directly adjacent comments belong to this header.
	for start > 0 && strings.HasPrefix(strings.TrimSpace(lines[start-1]), "#") {
		start--
	}
	var out []byte
	for _, line := range lines[:start] {
		out = append(out, line...)
	}
	for _, line := range lines[end:] {
		out = append(out, line...)
	}
	parsed, err := netprofile.Parse(out)
	if err != nil {
		return err
	}
	if _, still := parsed.Lookup(name); still {
		return refusal.New(refusal.CodeProfileInvalid, name, "profile is defined more than once; edit the file by hand")
	}
	return write(p, out, true)
}

func write(p Paths, out []byte, backup bool) error {
	if backup {
		if err := atomicfile.Backup(p.File, p.Backup); err != nil {
			return refusal.New(refusal.CodeFileUnreadable, BackupName, "cannot write the backup")
		}
	}
	if err := atomicfile.Write(p.File, out); err != nil {
		return refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "cannot write")
	}
	return nil
}

var anyHeader = regexp.MustCompile(`^[ \t]*\[`)

// headerPattern matches `[networks.<name>]` with optional whitespace, a
// bare or quoted key and an optional trailing comment.
func headerPattern(name string) *regexp.Regexp {
	q := regexp.QuoteMeta(name)
	return regexp.MustCompile(`^[ \t]*\[[ \t]*networks[ \t]*\.[ \t]*(?:"` + q + `"|'` + q + `'|` + q + `)[ \t]*\][ \t]*(?:#.*)?\r?$`)
}

// splitLines splits keeping line terminators, so a join reproduces the
// input byte for byte.
func splitLines(data []byte) []string {
	var lines []string
	s := string(data)
	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			lines = append(lines, s)
			break
		}
		lines = append(lines, s[:i+1])
		s = s[i+1:]
	}
	return lines
}

// renderBlock writes the table in the spec's layout. A name containing
// a dot is quoted (TOML would otherwise nest tables).
func renderBlock(prof netprofile.Profile) string {
	key := prof.Name
	if strings.Contains(key, ".") {
		key = strconv.Quote(key)
	}
	var b strings.Builder
	b.WriteString("[networks." + key + "]\n")
	if prof.Kind == netprofile.KindDirect {
		b.WriteString("kind = \"direct\"\n")
		return b.String()
	}
	b.WriteString("kind         = " + strconv.Quote(prof.Kind) + "\n")
	b.WriteString("endpoint     = " + strconv.Quote(prof.Endpoint) + "\n")
	quoted := make([]string, len(prof.BypassHosts))
	for i, h := range prof.BypassHosts {
		quoted[i] = strconv.Quote(h)
	}
	b.WriteString("bypass_hosts = [" + strings.Join(quoted, ", ") + "]\n")
	if prof.ProbeTarget != "" {
		b.WriteString("probe_target = " + strconv.Quote(prof.ProbeTarget) + "\n")
	}
	return b.String()
}
