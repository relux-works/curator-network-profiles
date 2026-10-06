// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

// darwinProfile is a policy specification for a future trusted supervisor,
// not an execution capability. Native enforcement/calibration is unimplemented;
// Probe refuses even if sandbox-exec happens to exist. The supervisor must
// independently discover/canonicalize all operator home and credential paths.
// Default-deny IPC includes all credential brokers; explicit denials below also
// name the actual SecurityServer/securityd services rather than just labels.
func darwinProfile(root, operatorHome, executable, addr string) (string, error) {
	clean := func(path string) bool {
		return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "\x00\r\n")
	}
	under := func(child, parent string) bool { return child == parent || strings.HasPrefix(child, parent+"/") }
	if !clean(root) || !clean(operatorHome) || !clean(executable) || under(root, operatorHome) || under(operatorHome, root) || !under(executable, filepath.Join(root, "stage")) {
		return "", &Unsupported{Reason: "isolation_layout_unsupported"}
	}
	host, port, err := net.SplitHostPort(addr)
	n, portErr := strconv.Atoi(port)
	if err != nil || host != "127.0.0.1" || portErr != nil || n < 1 || n > 65535 {
		return "", &Unsupported{Reason: "invalid_sink"}
	}
	q := strconv.Quote
	return fmt.Sprintf(`(version 1)
(deny default)
(allow file-read* (subpath "/System/Library") (subpath "/usr/lib") (subpath %s) (literal "/dev/null"))
(allow file-write* (subpath %s) (literal "/dev/null"))
(deny file-write* (subpath %s))
(deny file-read* file-write* (subpath %s) (subpath "/Library/Keychains") (subpath "/System/Library/Keychains") (subpath %s))
(deny mach-lookup)
(deny mach-lookup (global-name "com.apple.securityd") (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd.xpc") (global-name "com.apple.securityd.systemkeychain"))
(deny process-fork)
(allow process-exec (literal %s))
(deny network-outbound)
(allow network-outbound (remote ip %s))
`, q(root), q(root), q(filepath.Join(root, "stage")), q(operatorHome), q(filepath.Join(operatorHome, "Library", "Keychains")), q(executable), q("127.0.0.1:"+strconv.Itoa(n))), nil
}
