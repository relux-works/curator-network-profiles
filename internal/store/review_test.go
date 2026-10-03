// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"github.com/relux-works/curator-network-profiles/internal/store"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRemoveCommentOwnership(t *testing.T) {
	t.Parallel()
	prefix := "schema = \"relux-network-profiles-v1\"\n\n"
	block := func(name string) string {
		return "[networks." + name + "]\nkind = \"external-http-proxy\"\nendpoint = \"http://127.0.0.1:1\"\nbypass_hosts = [\"localhost\",\"127.0.0.1\",\"::1\"]\n"
	}
	a, b := block("a"), block("b")
	for _, tc := range []struct{ name, doc, want string }{
		{"first", prefix + "# own a\n# second own\n" + a + "\n# next b\n" + b, prefix + "\n# next b\n" + b},
		{"last", prefix + b + "\n# own a\n" + a + "\n# trailing notes\n\n", prefix + b + "\n\n# trailing notes\n\n"},
		{"only", prefix + "# own a\n" + a, prefix},
		{"blank separated", prefix + "# shared notes\n\n" + a + "\n# next b\n" + b, prefix + "# shared notes\n\n\n# next b\n" + b},
		{"eof without newline", prefix + "# own a\n" + strings.TrimSuffix(a, "\n"), prefix},
		{"crlf", strings.ReplaceAll(prefix+"# own a\n"+a+"\n# next b\n"+b, "\n", "\r\n"), strings.ReplaceAll(prefix+"\n# next b\n"+b, "\n", "\r\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := paths(t)
			seed(t, p, tc.doc)
			if err := store.Remove(p, "a"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(p.File)
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q (%v), want %q", got, err, tc.want)
			}
		})
	}
}

func TestEditsRefuseSymlinkCatalog(t *testing.T) {
	t.Parallel()
	for _, verb := range []string{"add", "remove"} {
		t.Run(verb, func(t *testing.T) {
			p := paths(t)
			seed(t, p, strings.Replace(seeded, "default = \"egress-a\"\n", "", 1))
			target := p.File + ".target"
			if err := os.Rename(p.File, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p.File); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(target)
			var err error
			if verb == "add" {
				err = store.Add(p, profile(t, "c", "http://127.0.0.1:1", nil, ""))
			} else {
				err = store.Remove(p, "egress-a")
			}
			if code, _ := refusal.CodeOf(err); code != refusal.CodeFileUnreadable || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("refusal: %v", err)
			}
			info, err := os.Lstat(p.File)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("symlink replaced")
			}
			after, _ := os.ReadFile(target)
			if string(before) != string(after) {
				t.Fatal("target changed")
			}
			if _, err := os.Stat(p.Backup); !os.IsNotExist(err) {
				t.Fatal("backup changed")
			}
		})
	}
}

func TestEditsRefuseHeldLock(t *testing.T) {
	t.Parallel()
	for _, verb := range []string{"add", "remove"} {
		t.Run(verb, func(t *testing.T) {
			p := paths(t)
			seed(t, p, seeded)
			if err := os.WriteFile(p.File+".lock", []byte("owner"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			if verb == "add" {
				err = store.Add(p, profile(t, "c", "http://127.0.0.1:1", nil, ""))
			} else {
				err = store.Remove(p, "egress-b")
			}
			if code, _ := refusal.CodeOf(err); code != refusal.CodeConfigurationConflict {
				t.Fatalf("lock was ignored: %v", err)
			}
			got, _ := os.ReadFile(p.File)
			if string(got) != seeded {
				t.Fatal("catalog changed")
			}
			lock, _ := os.ReadFile(p.File + ".lock")
			if string(lock) != "owner" {
				t.Fatal("another owner's lock changed")
			}
		})
	}
}

func TestEditsReleaseLockOnEveryReturn(t *testing.T) {
	t.Parallel()
	p := paths(t)
	prof := profile(t, "a", "http://127.0.0.1:1", nil, "")
	for _, edit := range []func() error{
		func() error { return store.Add(p, prof) },
		func() error { return store.Add(p, prof) },
		func() error { return store.Remove(p, "unknown") },
		func() error { return store.Remove(p, "a") },
	} {
		_ = edit()
		if _, err := os.Lstat(p.File + ".lock"); !os.IsNotExist(err) {
			t.Fatalf("lock left after edit: %v", err)
		}
	}
}

func TestConcurrentEditsRefuseWithoutLostUpdates(t *testing.T) {
	t.Parallel()
	p := paths(t)
	seed(t, p, seeded)
	acquired, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- store.Edit(p, func(e *store.Editor) error { close(acquired); <-release; return e.Remove("egress-b") })
	}()
	<-acquired
	// Defer the release so a failed assertion cannot strand the owner.
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	for _, edit := range []func() error{
		func() error { return store.Add(p, profile(t, "c", "http://127.0.0.1:1", nil, "")) },
		func() error { return store.Remove(p, "egress-b") },
	} {
		if code, _ := refusal.CodeOf(edit()); code != refusal.CodeConfigurationConflict {
			t.Errorf("concurrent edit was accepted")
		}
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("edit did not finish")
	}
	f, _, err := store.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Lookup("egress-b"); ok {
		t.Fatal("owner's remove lost")
	}
	if _, ok := f.Lookup("egress-a"); !ok {
		t.Fatal("unrelated profile lost")
	}
	if err := store.Add(p, profile(t, "c", "http://127.0.0.1:1", nil, "")); err != nil {
		t.Fatalf("retry after owner completed: %v", err)
	}
}
