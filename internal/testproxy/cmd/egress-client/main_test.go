// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestDumpProxyEnvironmentDoesNotDial(t *testing.T) {
	for _, tc := range []struct {
		name      string
		env, want []string
	}{
		{"clean", []string{"PATH=/bin", "GOPROXY=off"}, []string{}},
		{"hostile", []string{"PATH=/bin", "HTTPS_PROXY=http://127.0.0.1:1", "Http_Proxy=http://127.0.0.1:1", "NO_PROXY=*"}, []string{"HTTPS_PROXY=http://127.0.0.1:1", "Http_Proxy=http://127.0.0.1:1", "NO_PROXY=*"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := dumpProxyEnv(tc.env, &out); code != 0 {
				t.Fatalf("dump = %d", code)
			}
			var got []string
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("dump = %v, want %v", got, tc.want)
			}
		})
	}
	var out, diag bytes.Buffer
	// An invalid URL proves dump mode returns before URL handling or dialing.
	if code := run([]string{"--dump-proxy-env", "--url", ":invalid"}, &out, &diag); code != 0 || diag.Len() != 0 {
		t.Fatalf("run = %d, %s", code, &diag)
	}
}
