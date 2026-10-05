// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/relux-works/curator-network-profiles/internal/confirm"
	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// Binding changes require operator presence even when the target digest is
// already confirmed. Prompt before locking, then refuse any catalog change.
func (a *app) editBinding(args []string, unbind bool) int {
	verb, schema, count := "bind", SchemaBind, 2
	if unbind {
		verb, schema, count = "unbind", SchemaUnbind, 1
	}
	pos, code, ok := a.operands(a.flagSet(verb), args, count, count)
	if !ok {
		return code
	}
	if err := confirm.GuardCommand(a.deps.Env, a.deps.IsTerminal(), verb); err != nil {
		return a.fail(err)
	}
	for _, name := range pos {
		if err := netprofile.ValidateName(name); err != nil {
			return a.fail(err)
		}
	}
	profile, network := pos[0], ""
	if !unbind {
		network = pos[1]
	}
	paths, err := store.PathsFromEnv(a.deps.Env)
	if err != nil {
		return a.fail(err)
	}
	file, shown, err := store.Read(paths)
	if err != nil {
		return a.fail(err)
	}
	previous := ""
	if file != nil {
		previous = file.Bindings.Profiles[profile]
	}
	if unbind && previous == "" {
		return a.fail(refusal.New(refusal.CodeProfileUnknown, profile, "no operator binding for this Curator profile"))
	}
	if !unbind {
		if _, found := file.Lookup(network); !found {
			return a.fail(refusal.New(refusal.CodeProfileUnknown, network, "no such network profile on this machine"))
		}
	}
	prompt := a.deps.Stdout
	if a.json {
		prompt = a.deps.Stderr
	}
	if unbind {
		fmt.Fprintf(prompt, "Remove operator binding %s -> %s. Lower-priority defaults may take effect.\n", profile, previous)
	} else {
		fmt.Fprintf(prompt, "Set operator binding %s -> %s (previous: %s). Target digest confirmation is separate.\n", profile, network, previous)
	}
	fmt.Fprintf(prompt, "Type `yes` to %s: ", verb)
	line, _ := bufio.NewReader(a.deps.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		fmt.Fprintln(prompt)
		return a.fail(refusal.New(refusal.CodeConfirmRefused, "operator", "not confirmed (the answer was not `yes`)"))
	}
	err = store.Edit(paths, func(e *store.Editor) error {
		current, err := os.ReadFile(paths.File)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return refusal.New(refusal.CodeFileUnreadable, netprofile.FileName, "cannot read")
		}
		if !bytes.Equal(shown, current) {
			return refusal.New(refusal.CodeConfigurationConflict, netprofile.FileName, "catalog changed during binding confirmation; run the command again")
		}
		if unbind {
			return e.Unbind(profile)
		}
		return e.Bind(profile, network)
	})
	if err != nil {
		return a.fail(err)
	}
	if a.json {
		a.emit(struct {
			Schema         string `json:"schema"`
			OK             bool   `json:"ok"`
			CuratorProfile string `json:"curator_profile"`
			Network        string `json:"network,omitempty"`
			Previous       string `json:"previous,omitempty"`
		}{schema, true, profile, network, previous})
	} else if unbind {
		fmt.Fprintf(a.deps.Stdout, "unbound %s\n", profile)
	} else {
		fmt.Fprintf(a.deps.Stdout, "bound %s -> %s\n", profile, network)
	}
	return ExitOK
}
