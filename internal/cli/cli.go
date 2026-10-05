// SPDX-License-Identifier: Apache-2.0

// Package cli implements the provider `curator-network`, which the
// umbrella calls as `curator network <verb> …` (argv[1:] = verb …).
//
// Exit codes: 0 ok, 1 refusal or failure, 2 usage. Human output goes to
// stdout; diagnostics `curator-network: <code>: <detail>` go to stderr.
// `--json` on every verb prints a versioned document on stdout: success
// `{"schema":"curator-network-<verb>-v1","ok":true,…}`, refusal
// `{"schema":"curator-network-error-v1","ok":false,"error":{…}}` with
// exit 1. Usage errors never produce JSON.
//
// Every process boundary comes through Deps: the environment, the
// standard streams, the terminal test, exec, the prober and the clock.
// There are no package-level test seams and nothing reads os.Getenv.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/relux-works/curator-network-profiles/internal/version"
	"github.com/relux-works/curator-network-profiles/pkg/probe"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

// Name is the executable name used in diagnostics.
const Name = "curator-network"

// Versioned schema ids of the JSON documents.
const (
	SchemaVersion = "curator-network-version-v1"
	SchemaList    = "curator-network-list-v1"
	SchemaShow    = "curator-network-show-v1"
	SchemaAdd     = "curator-network-add-v1"
	SchemaRemove  = "curator-network-remove-v1"
	SchemaBind    = "curator-network-bind-v1"
	SchemaUnbind  = "curator-network-unbind-v1"
	SchemaCheck   = "curator-network-check-v1"
	SchemaConfirm = "curator-network-confirm-v1"
	SchemaExec    = "curator-network-exec-v1"
	SchemaError   = "curator-network-error-v1"
)

// Exit statuses.
const (
	ExitOK      = 0
	ExitRefused = 1
	ExitUsage   = 2
)

// Deps are the process boundaries. Production fills them from the
// process; tests inject fakes.
type Deps struct {
	// Env is the inherited environment; HOME and PATH are read from it.
	Env []string
	// Stdin is read by operator confirmation prompts.
	Stdin io.Reader
	// Stdout and Stderr receive human or JSON output and diagnostics.
	Stdout io.Writer
	Stderr io.Writer
	// IsTerminal reports whether stdin is an operator terminal.
	IsTerminal func() bool
	// Exec replaces the process (syscall.Exec); it returns only on failure.
	Exec func(path string, argv []string, env []string) error
	// Prober runs preflights; `check` without --probe never calls it.
	Prober probe.Prober
	// Now is the clock for confirmations.
	Now func() time.Time
}

// Usage is the command synopsis.
const Usage = `usage: curator-network [--json] <verb> [arguments]

  list                                      profiles of ~/.curator/network.toml
  show <name>                               one profile, its digest and its patch
  add <name> --direct
  add <name> --endpoint http://host:port    [--bypass h1,h2] [--probe-target host:port]
  remove <name>                             narrowing; applies immediately
  bind <curator-profile> <network>           operator terminal only
  unbind <curator-profile>                   operator terminal only
  check [<name>|--all] [--probe]            [--target host:port] [--timeout 3s]
  confirm [<name>...]                       operator terminal only
  exec <name> [--preflight-timeout 3s] [--dry-run] -- <command> [arguments...]
  --version

Every verb accepts --json. Exit: 0 ok, 1 refusal, 2 usage.
`

type app struct {
	ctx  context.Context
	deps Deps
	json bool
}

// Run executes args and returns the exit status.
func Run(ctx context.Context, args []string, deps Deps) int {
	if deps.Stdout == nil {
		deps.Stdout = io.Discard
	}
	if deps.Stderr == nil {
		deps.Stderr = io.Discard
	}
	if deps.Stdin == nil {
		deps.Stdin = strings.NewReader("")
	}
	if deps.IsTerminal == nil {
		deps.IsTerminal = func() bool { return false }
	}
	if deps.Exec == nil {
		deps.Exec = func(string, []string, []string) error { return errors.New("exec is not available") }
	}
	if deps.Prober == nil {
		deps.Prober = &probe.Dialer{}
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	a := &app{ctx: ctx, deps: deps}

	versionFlag, helpFlag := false, false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "--json":
			a.json = true
		case "--version", "-V":
			versionFlag = true
		case "--help", "-h", "help":
			helpFlag = true
		default:
			return a.usage("unknown option")
		}
		args = args[1:]
	}
	if helpFlag {
		fmt.Fprint(deps.Stdout, Usage)
		return ExitOK
	}
	if versionFlag {
		if len(args) != 0 {
			return a.usage("--version: unexpected operand")
		}
		return a.version()
	}
	if len(args) == 0 {
		return a.usage("a verb is required")
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "version":
		if _, code, ok := a.operands(a.flagSet("version"), rest, 0, 0); !ok {
			return code
		}
		return a.version()
	case "help":
		fmt.Fprint(deps.Stdout, Usage)
		return ExitOK
	case "list":
		return a.list(rest)
	case "show":
		return a.show(rest)
	case "add":
		return a.add(rest)
	case "remove":
		return a.remove(rest)
	case "bind":
		return a.editBinding(rest, false)
	case "unbind":
		return a.editBinding(rest, true)
	case "check":
		return a.check(rest)
	case "confirm":
		return a.confirm(rest)
	case "exec":
		return a.exec(rest)
	default:
		return a.usage("unknown verb")
	}
}

// flagSet builds a verb flag set that never prints by itself and always
// carries --json.
func (a *app) flagSet(verb string) *flag.FlagSet {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&a.json, "json", a.json, "machine-readable output")
	return fs
}

// parseInterspersed parses flags before and after positional operands
// and returns the operands. The first -- ends flag parsing for the verb.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional, trailing []string
	for i, arg := range args {
		if arg == "--" {
			trailing = args[i+1:]
			args = args[:i]
			break
		}
	}
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, safeFlagError(fs, err)
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return append(positional, trailing...), nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}

// safeFlagError discards flag's raw error, which may contain an operand or
// value. Only names registered by this program may appear in a diagnostic.
func safeFlagError(fs *flag.FlagSet, err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return flag.ErrHelp
	}
	detail := "invalid flag"
	fs.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(err.Error(), "invalid value ") && strings.Contains(err.Error(), " for flag -"+f.Name+":") {
			detail = "invalid value for flag -" + f.Name
		} else if err.Error() == "flag needs an argument: -"+f.Name {
			detail = "flag -" + f.Name + " requires a value"
		}
	})
	return errors.New(detail)
}

// operands parses a verb's arguments; it reports usage errors itself
// and returns ok=false with the exit status to return.
func (a *app) operands(fs *flag.FlagSet, args []string, min, max int) ([]string, int, bool) {
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(a.deps.Stdout, Usage)
		return nil, ExitOK, false
	}
	if err != nil {
		return nil, a.usage(fs.Name() + ": " + err.Error()), false
	}
	if len(pos) < min {
		return nil, a.usage(fs.Name() + ": missing operand"), false
	}
	if max >= 0 && len(pos) > max {
		return nil, a.usage(fs.Name() + ": unexpected operand"), false
	}
	return pos, ExitOK, true
}

func (a *app) usage(detail string) int {
	fmt.Fprintf(a.deps.Stderr, "%s: usage: %s\n\n%s", Name, detail, Usage)
	return ExitUsage
}

// errorBody is the JSON error object.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Subject string `json:"subject"`
}

func bodyOf(err error) errorBody {
	if r, ok := refusal.As(err); ok {
		safe := refusal.New(r.Code, r.Subject, r.Detail)
		return errorBody{Code: safe.Code, Message: safe.Error(), Subject: safe.Subject}
	}
	// TODO(decision): unexpected internal failures use the existing conflict
	// code; no implementation detail or new code crosses the boundary.
	r := refusal.New(refusal.CodeConfigurationConflict, "", "internal operation failed")
	return errorBody{Code: r.Code, Message: r.Error(), Subject: r.Subject}
}

// fail reports a refusal on stderr (and as a JSON document on stdout
// under --json) and returns exit 1.
func (a *app) fail(err error) int {
	body := bodyOf(err)
	a.diag(body.Code, strings.TrimPrefix(body.Message, body.Code+": "))
	if a.json {
		a.emit(struct {
			Schema string    `json:"schema"`
			OK     bool      `json:"ok"`
			Error  errorBody `json:"error"`
		}{SchemaError, false, body})
	}
	return ExitRefused
}

// diag writes one `curator-network: <code>: <detail>` line; embedded
// line breaks in detail are indented so only the first line is a code line.
func (a *app) diag(code, detail string) {
	detail = strings.ReplaceAll(detail, "\r\n", "\n")
	detail = strings.ReplaceAll(detail, "\r", "\n")
	detail = strings.ReplaceAll(detail, "\n", "\n  ")
	fmt.Fprintf(a.deps.Stderr, "%s: %s: %s\n", Name, code, detail)
}

// emit writes one compact JSON document on stdout.
func (a *app) emit(v any) {
	enc := json.NewEncoder(a.deps.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (a *app) version() int {
	info := version.Get()
	if a.json {
		a.emit(struct {
			Schema string `json:"schema"`
			OK     bool   `json:"ok"`
			Name   string `json:"name"`
			version.Info
		}{SchemaVersion, true, Name, info})
		return ExitOK
	}
	fmt.Fprintln(a.deps.Stdout, info.Line(Name))
	return ExitOK
}
