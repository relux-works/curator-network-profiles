// SPDX-License-Identifier: Apache-2.0

package store

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// Bind sets or replaces a profile default under the lock held by Edit.
// The target must exist; confirmation of its digest is a separate operation.
func (e *Editor) Bind(profile, network string) error {
	if err := netprofile.ValidateName(network); err != nil {
		return err
	}
	return e.editBinding(profile, network)
}

// Unbind removes a profile default under the lock held by Edit.
func (e *Editor) Unbind(profile string) error { return e.editBinding(profile, "") }

var profilesHeader = regexp.MustCompile(`^[ \t]*\[[ \t]*(?:bindings|"bindings"|'bindings')[ \t]*\.[ \t]*(?:profiles|"profiles"|'profiles')[ \t]*\][ \t]*(?:#.*)?\r?\n?$`)

func (e *Editor) editBinding(profile, network string) error {
	if err := netprofile.ValidateName(profile); err != nil {
		return err
	}
	f, data, err := Read(e.paths)
	if err != nil {
		return err
	}
	if network != "" {
		if _, ok := f.Lookup(network); !ok {
			return refusal.New(refusal.CodeProfileUnknown, network, "no such network profile on this machine")
		}
	}
	old, exists := "", false
	if f != nil {
		old, exists = f.Bindings.Profiles[profile]
	}
	if network == "" && !exists {
		return refusal.New(refusal.CodeProfileUnknown, profile, "no operator binding for this Curator profile")
	}
	if exists && old == network {
		return nil
	}
	lines := splitLines(data)
	start, end := -1, len(lines)
	for i, line := range lines {
		if profilesHeader.MatchString(line) {
			start = i
			continue
		}
		if start >= 0 && anyHeader.MatchString(line) {
			end = i
			break
		}
	}
	unsupported := func() error {
		return bindingLayoutError(profile)
	}
	entry := strconv.Quote(profile) + " = " + strconv.Quote(network) + "\n"
	if start < 0 {
		if exists || (f != nil && len(f.Bindings.Profiles) > 0) {
			return unsupported()
		}
		out := strings.TrimSuffix(string(data), "\n") + "\n\n[bindings.profiles]\n" + entry
		return e.writeBinding([]byte(out), profile, network)
	}
	if exists {
		q := regexp.QuoteMeta(profile)
		assignment := regexp.MustCompile(`^([ \t]*(?:` + q + `|"` + q + `"|'` + q + `')[ \t]*=[ \t]*)(?:"(?:[^"\\]|\\.)*"|'[^']*')([ \t]*(?:#.*)?\r?)(\n?)$`)
		found := false
		for i := start + 1; i < end; i++ {
			parts := assignment.FindStringSubmatch(lines[i])
			if parts == nil {
				continue
			}
			if network == "" {
				lines[i] = ""
			} else {
				lines[i] = parts[1] + strconv.Quote(network) + parts[2] + parts[3]
			}
			found = true
			break
		}
		if !found {
			return unsupported()
		}
	} else {
		// Insert immediately after the header, keeping all other bytes.
		lines[start] = strings.TrimSuffix(lines[start], "\n") + "\n" + entry
	}
	return e.writeBinding([]byte(strings.Join(lines, "")), profile, network)
}

func (e *Editor) writeBinding(out []byte, profile, network string) error {
	f, err := netprofile.Parse(out)
	if err != nil {
		// The original catalog was validated by Read. An invalid candidate
		// means the text editor cannot handle its layout (including empty
		// inline tables), rather than an invalid operator catalog.
		return bindingLayoutError(profile)
	}
	got, exists := f.Bindings.Profiles[profile]
	if (network == "" && exists) || (network != "" && (!exists || got != network)) {
		return refusal.New(refusal.CodeProfileInvalid, profile, "the edited file does not round-trip the binding")
	}
	return write(e.paths, out, true)
}

func bindingLayoutError(profile string) error {
	return refusal.New(refusal.CodeProfileInvalid, profile, "binding is not a single-line entry in [bindings.profiles]; edit the file by hand")
}
