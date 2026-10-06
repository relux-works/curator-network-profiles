// SPDX-License-Identifier: Apache-2.0
package adapterprobe

// Synthetic test-only recipes. The production registry carries only real
// vendor lines; these entries exist so private cache-fixture tests can
// exercise the evidence seam end to end without real-vendor qualification.
// They must never ship as known vendor lines.
func init() {
	recipes["fake-http-v1"] = recipe{Harness: "fake-harness", Entrypoint: "exec", Argv: []string{"--probe-http"}, Expected: Observation{Kind: "absolute-URI", Target: "probe.invalid:80"}}
	recipes["fake-connect-v1"] = recipe{Harness: "fake-harness", Entrypoint: "exec", Argv: []string{"--probe-connect"}, Expected: Observation{Kind: "CONNECT", Target: "probe.invalid:443"}}
}
