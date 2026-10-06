// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// KnownBadSchema versions the known-bad list document.
const KnownBadSchema = "relux-adapter-knownbad-v1"

// KnownBadFileName is the fixed operator filename relative to the
// explicitly supplied operator configuration root (for example,
// ~/.curator/adapter-knownbad.json). The library never discovers the
// root itself; callers pass it to LoadKnownBad.
const KnownBadFileName = "adapter-knownbad.json"

// MaxKnownBadBytes bounds the operator known-bad file read.
const MaxKnownBadBytes = 1 << 20

// embeddedKnownBadSHA256 is the shipped known-bad list: binary SHA-256
// digests (64 lowercase hex) refused on every evaluation. It is empty;
// releases add entries only for positively identified bad builds.
var embeddedKnownBadSHA256 = []string{}

// KnownBad is a set of refused binary SHA-256 digests.
type KnownBad struct {
	digests map[string]bool
}

// EmbeddedKnownBad returns the shipped list. The result is a fresh set.
func EmbeddedKnownBad() *KnownBad {
	return &KnownBad{digests: digestSet(embeddedKnownBadSHA256)}
}

func digestSet(digests []string) map[string]bool {
	out := make(map[string]bool, len(digests))
	for _, d := range digests {
		out[d] = true
	}
	return out
}

// ParseKnownBad parses operator known-bad list bytes. The document must
// be a closed JSON object with exactly the members "schema" (string)
// and "sha256" (array of strings); both are required. Member spellings
// are exact and case-sensitive, duplicates refuse, unknown members
// refuse, and trailing data refuses. Entries must be 64 lowercase hex.
// Null, missing or wrong-typed members refuse as corrupt, never as an
// empty set. A single well-formed unsupported schema refuses as
// knownbad_version_unsupported; any duplicate or ambiguous schema
// refuses as knownbad_corrupt. Raw contents never enter refusals.
//
// An unknown schema with a null or invalid digest element refuses as
// knownbad_corrupt: the version reason needs a single well-formed
// document with every element a valid digest. JSON escapes that decode
// to the same member name meet the same duplicate check.
//
// Callers obtain bytes via LoadKnownBad (which owns the file location
// and absent/unreadable semantics) and carry failures into Evaluate via
// Policy.KnownBadErr so evaluation fails closed.
func ParseKnownBad(data []byte) (*KnownBad, error) {
	corrupt := &Unsupported{Reason: "knownbad_corrupt"}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, corrupt
	}
	seen := make(map[string]bool, 2)
	var schema string
	var digests []string
	schemaSet, listSet := false, false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, corrupt
		}
		key, ok := tok.(string)
		if !ok {
			return nil, corrupt
		}
		if seen[key] {
			return nil, corrupt
		}
		seen[key] = true
		switch key {
		case "schema":
			var s *string
			if err := dec.Decode(&s); err != nil || s == nil {
				return nil, corrupt
			}
			schema, schemaSet = *s, true
		case "sha256":
			tok, err := dec.Token()
			if err != nil || tok != json.Delim('[') {
				return nil, corrupt
			}
			var list []string
			for dec.More() {
				var s *string
				if err := dec.Decode(&s); err != nil || s == nil {
					return nil, corrupt
				}
				list = append(list, *s)
			}
			tok, err = dec.Token()
			if err != nil || tok != json.Delim(']') {
				return nil, corrupt
			}
			digests, listSet = list, true
		default:
			return nil, corrupt
		}
	}
	tok, err = dec.Token()
	if err != nil || tok != json.Delim('}') {
		return nil, corrupt
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, corrupt
	}
	if !schemaSet || !listSet {
		return nil, corrupt
	}
	if digests == nil {
		digests = []string{}
	}
	for _, d := range digests {
		if !digestRE.MatchString(d) {
			return nil, corrupt
		}
	}
	if schema == "" {
		return nil, corrupt
	}
	if schema != KnownBadSchema {
		return nil, &Unsupported{Reason: "knownbad_version_unsupported"}
	}
	return &KnownBad{digests: digestSet(digests)}, nil
}

// KnownBadReadFunc reads one operator file. It must report a genuinely
// absent file with an error wrapping os.ErrNotExist and every other
// failure (permission, directory, symlink, FIFO, non-regular file, too
// large, disappearance or replacement between inspection and open) with
// a different error. Production callers pass SafeKnownBadRead; tests
// inject fakes, inject filesystem operations into safeKnownBadRead, or
// call SafeKnownBadRead on disposable inert files. Paths and raw file
// bytes never enter the mapped refusal.
type KnownBadReadFunc func(path string) ([]byte, error)

// SafeKnownBadRead is the production KnownBadReadFunc. It inspects the
// directory entry without following symlinks and requires it to be a
// regular file, opens with no-follow and nonblocking guarantees before
// any descriptor validation, requires the opened descriptor to be the
// same regular file that was inspected, and bounds the read at
// MaxKnownBadBytes. Symbolic links are never followed: any symlink at
// the operator path refuses as unreadable. Only a genuinely absent
// entry (no directory entry at inspection) reports os.ErrNotExist; a
// disappearance or replacement after a successful inspection refuses as
// unreadable, never as absent. Where a no-follow nonblocking open is
// unavailable, present files refuse closed without being read.
func SafeKnownBadRead(path string) ([]byte, error) {
	return safeKnownBadRead(path, os.Lstat, openKnownBadFile)
}

// safeKnownBadRead is SafeKnownBadRead with injected inspection/open
// operations so tests can deterministically exercise the
// inspection-to-open race. Production passes os.Lstat and
// openKnownBadFile.
func safeKnownBadRead(path string, lstat func(string) (os.FileInfo, error), open func(string) (*os.File, error)) ([]byte, error) {
	fi, err := lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, errors.New("known-bad file is not accessible")
	}
	if fi == nil || !fi.Mode().IsRegular() {
		return nil, errors.New("known-bad file is not a regular file")
	}
	f, err := open(path)
	if err != nil {
		// Any open failure after a successful inspection — including an
		// ENOENT from a deletion race or an ELOOP from a symlink
		// replacement — is a present-but-unusable path, never optional
		// absence. The raw error is sanitized so it cannot read as
		// a genuine absence.
		return nil, errors.New("known-bad file is not accessible")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || opened == nil || !opened.Mode().IsRegular() {
		return nil, errors.New("known-bad file is not a regular file")
	}
	if !os.SameFile(fi, opened) {
		// A different file replaced the inspected regular entry
		// between inspection and open. The replacement's bytes are
		// never read: this is a present-but-unusable path, never
		// optional absence, and the error is sanitized so it cannot
		// read as a genuine absence.
		return nil, errors.New("known-bad file is not accessible")
	}
	if opened.Size() > MaxKnownBadBytes {
		return nil, errors.New("known-bad file too large")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxKnownBadBytes+1))
	if err != nil {
		return nil, errors.New("known-bad file is not accessible")
	}
	if int64(len(data)) > MaxKnownBadBytes {
		return nil, errors.New("known-bad file too large")
	}
	return data, nil
}

// LoadKnownBad loads the operator known-bad list and merges it with the
// embedded list. configRoot is the explicitly supplied operator
// configuration root; explicitPath, when non-empty, is the explicitly
// configured operator file and wins over the default.
//
//   - Optional default (explicitPath empty): configRoot/KnownBadFileName
//     genuinely absent means the embedded set only. Present but
//     unreadable, non-regular, symlink, FIFO, directory, too large,
//     empty, malformed or ambiguous refuses, as does a deletion or
//     replacement between inspection and open.
//   - Explicit file: missing, unreadable, symlink, FIFO, directory,
//     non-regular, too large, empty, malformed or ambiguous refuses
//     with knownbad_unreadable or knownbad_corrupt; a single
//     well-formed unknown schema refuses with
//     knownbad_version_unsupported.
//   - Valid file: its digests are added to the embedded set. Symbolic
//     links are never followed, even to a valid file.
//
// On success it returns the merged set and a nil error. On failure it
// returns a nil set and a typed Unsupported to carry into
// Policy.KnownBadErr; Evaluate refuses before any other input. Evaluate
// itself remains I/O-free. Empty configRoot with empty explicitPath
// means no operator file: the embedded set only.
func LoadKnownBad(read KnownBadReadFunc, configRoot, explicitPath string) (*KnownBad, error) {
	if read == nil {
		return nil, &Unsupported{Reason: "knownbad_unreadable"}
	}
	if explicitPath == "" && configRoot == "" {
		return EmbeddedKnownBad(), nil
	}
	path := explicitPath
	explicit := true
	if path == "" {
		path = filepath.Join(configRoot, KnownBadFileName)
		explicit = false
	}
	data, err := read(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return EmbeddedKnownBad(), nil
		}
		return nil, &Unsupported{Reason: "knownbad_unreadable"}
	}
	operator, err := ParseKnownBad(data)
	if err != nil {
		return nil, err
	}
	return EmbeddedKnownBad().Union(operator), nil
}

// Union merges two sets. Nil inputs are treated as empty.
func (k *KnownBad) Union(other *KnownBad) *KnownBad {
	out := &KnownBad{digests: map[string]bool{}}
	for _, set := range []*KnownBad{k, other} {
		if set == nil {
			continue
		}
		for d := range set.digests {
			out.digests[d] = true
		}
	}
	return out
}

// Contains reports whether the binary SHA-256 (64 lowercase hex, not
// the BuildID form) is listed.
func (k *KnownBad) Contains(digest string) bool {
	if k == nil {
		return false
	}
	return k.digests[digest]
}
