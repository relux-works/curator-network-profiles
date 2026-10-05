// SPDX-License-Identifier: Apache-2.0

package hosted_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/curator-network-profiles/pkg/hosted"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
)

func carrier() hosted.Carrier {
	return hosted.Carrier{Schema: hosted.Schema, SchemaVersion: hosted.SchemaVersion,
		Ref: "egress-a", Origin: hosted.OriginExplicit, ExpectedDigest: "sha256:" + strings.Repeat("4", 64)}
}

func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	if code, ok := refusal.CodeOf(err); !ok || code != want {
		t.Fatalf("error = %v; want %s", err, want)
	}
}

func TestCarrierCanonical(t *testing.T) {
	c := carrier()
	data, err := hosted.EncodeCarrier(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"expected_digest":"sha256:` + strings.Repeat("4", 64) + `","origin":"explicit","ref":"egress-a","schema":"urn:relux:task-board:network-binding","schema_version":"1.0.0"}`
	if string(data) != want {
		t.Fatalf("encoding = %s", data)
	}
	got, err := hosted.DecodeCarrier(data)
	if err != nil || got != c {
		t.Fatalf("round trip = %+v %v", got, err)
	}
	data = []byte(`{"schema":"` + hosted.Schema + `","schema_version":"1.0.0","ref":"egress-a","origin":"explicit","expected_digest":"` + c.ExpectedDigest + `"}`)
	got, err = hosted.DecodeCarrier(data)
	if err != nil || got != c {
		t.Fatalf("noncanonical input = %+v %v", got, err)
	}
	for _, origin := range []hosted.Origin{hosted.OriginExplicit, hosted.OriginInherited, hosted.OriginRuntime, hosted.OriginProject, hosted.OriginOperator} {
		c.Origin = origin
		data, err := hosted.EncodeCarrier(c)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := hosted.DecodeCarrier(data); err != nil || got != c {
			t.Fatalf("origin %s: %+v %v", origin, got, err)
		}
	}
}

func TestCarrierV1RefusesProfileBindingOrigin(t *testing.T) {
	c := carrier()
	data, err := hosted.EncodeCarrier(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Origin = hosted.Origin("profile-binding")
	_, err = hosted.EncodeCarrier(c)
	requireCode(t, err, refusal.CodeConfigurationConflict)
	data = []byte(strings.Replace(string(data), `"origin":"explicit"`, `"origin":"profile-binding"`, 1))
	_, err = hosted.DecodeCarrier(data)
	requireCode(t, err, refusal.CodeConfigurationConflict)
}

func TestNestedCarrierDecoder(t *testing.T) {
	var payload struct {
		Network *hosted.Carrier `json:"network"`
	}
	if err := json.Unmarshal([]byte(`{"network":null}`), &payload); err != nil || payload.Network != nil {
		t.Fatalf("unmanaged payload: %+v %v", payload, err)
	}
	data, _ := hosted.EncodeCarrier(carrier())
	if err := json.Unmarshal([]byte(`{"network":`+string(data)+`}`), &payload); err != nil || payload.Network == nil || *payload.Network != carrier() {
		t.Fatalf("managed payload: %+v %v", payload, err)
	}
	duplicate := strings.TrimSuffix(string(data), "}") + `,"ref":"other"}`
	if err := json.Unmarshal([]byte(`{"network":`+duplicate+`}`), &payload); err == nil {
		t.Fatal("nested decoder accepted duplicate")
	}
	got, err := json.Marshal(carrier())
	if err != nil || string(got) != string(data) {
		t.Fatalf("MarshalJSON = %s %v", got, err)
	}
}

func TestCarrierMalformedTable(t *testing.T) {
	data, _ := hosted.EncodeCarrier(carrier())
	valid := string(data)
	bad := map[string]string{
		"empty": "", "null": "null", "array": "[]", "empty object": "{}",
		"nested":            strings.Replace(valid, `"ref":"egress-a"`, `"ref":{}`, 1),
		"null member":       strings.Replace(valid, `"origin":"explicit"`, `"origin":null`, 1),
		"number":            strings.Replace(valid, `"ref":"egress-a"`, `"ref":1`, 1),
		"unknown":           strings.TrimSuffix(valid, "}") + `,"secret":"CANARY://user:pass"}`,
		"duplicate":         strings.TrimSuffix(valid, "}") + `,"ref":"egress-b"}`,
		"escaped duplicate": strings.TrimSuffix(valid, "}") + `,"r\u0065f":"egress-b"}`,
		"case alias":        strings.Replace(valid, `"ref":`, `"Ref":`, 1),
		"missing":           strings.Replace(valid, `,"ref":"egress-a"`, "", 1),
		"trailing object":   valid + " {}", "trailing junk": valid + "x",
		"truncated": valid[:len(valid)-1], "comma": strings.TrimSuffix(valid, "}") + ",}",
		"oversize":         valid + strings.Repeat(" ", hosted.MaxCarrierBytes),
		"invalid UTF8":     valid + string([]byte{0xff}),
		"URL ref":          strings.Replace(valid, "egress-a", "http://user:pass@secret.invalid:1", 1),
		"uppercase ref":    strings.Replace(valid, "egress-a", "Egress-a", 1),
		"trailing dot":     strings.Replace(valid, "egress-a", "egress.", 1),
		"device":           strings.Replace(valid, "egress-a", "con", 1),
		"device extension": strings.Replace(valid, "egress-a", "com1.txt", 1),
		"long ref":         strings.Replace(valid, "egress-a", strings.Repeat("a", 64), 1),
		"bad origin":       strings.Replace(valid, "explicit", "runtime-default", 1),
		"short digest":     strings.Replace(valid, strings.Repeat("4", 64), "4", 1),
		"uppercase digest": strings.Replace(valid, strings.Repeat("4", 64), strings.Repeat("A", 64), 1),
	}
	for name, input := range bad {
		t.Run(name, func(t *testing.T) {
			got, err := hosted.DecodeCarrier([]byte(input))
			requireCode(t, err, refusal.CodeConfigurationConflict)
			if got != (hosted.Carrier{}) {
				t.Fatalf("partial carrier: %+v", got)
			}
			if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "secret.invalid") {
				t.Fatal("input leaked in refusal")
			}
		})
	}
	for _, input := range []string{strings.Replace(valid, hosted.Schema, "foreign", 1), strings.Replace(valid, "1.0.0", "2.0.0", 1)} {
		_, err := hosted.DecodeCarrier([]byte(input))
		requireCode(t, err, refusal.CodeScopeUnsupported)
	}
	for _, ref := range []string{"a", "con-safe", "com0", "lpt10", "a_b-", strings.Repeat("a", 63)} {
		c := carrier()
		c.Ref = ref
		if _, err := hosted.EncodeCarrier(c); err != nil {
			t.Fatalf("valid ref %s: %v", ref, err)
		}
	}
	c := carrier()
	c.ExpectedDigest = "bad"
	if data, err := hosted.EncodeCarrier(c); err == nil || data != nil {
		t.Fatal("invalid carrier encoded")
	}
}

func TestCarrierDispatchOrder(t *testing.T) {
	const canary = "CANARY://user:pass@private.invalid"
	fields := []struct {
		name    string
		members []string
	}{
		{"complete", []string{`"ref":"egress-a"`, `"origin":"explicit"`, `"expected_digest":"` + carrier().ExpectedDigest + `"`}},
		{"extra", []string{`"ref":"egress-a"`, `"origin":"explicit"`, `"expected_digest":"` + carrier().ExpectedDigest + `"`, `"future_option":{"secret":["` + canary + `",true,42]}`}},
		{"missing ref", []string{`"origin":"explicit"`, `"expected_digest":"` + carrier().ExpectedDigest + `"`}},
		{"dispatch only", nil},
		{"wrong types", []string{`"ref":{}`, `"origin":null`, `"expected_digest":42`}},
		{"case alias", []string{`"Ref":"egress-a"`, `"origin":"explicit"`, `"expected_digest":"` + carrier().ExpectedDigest + `"`}},
	}
	dispatches := []struct {
		name, schema, version, code string
	}{
		{"known", `"` + hosted.Schema + `"`, `"1.0.0"`, refusal.CodeConfigurationConflict},
		{"unknown schema", `"foreign"`, `"1.0.0"`, refusal.CodeScopeUnsupported},
		{"unknown version", `"` + hosted.Schema + `"`, `"2.0.0"`, refusal.CodeScopeUnsupported},
		{"both unknown", `"foreign"`, `"2.0.0"`, refusal.CodeScopeUnsupported},
		{"missing schema", "", `"2.0.0"`, refusal.CodeConfigurationConflict},
		{"missing version", `"foreign"`, "", refusal.CodeConfigurationConflict},
		{"empty schema", `""`, `"2.0.0"`, refusal.CodeConfigurationConflict},
		{"empty version", `"foreign"`, `""`, refusal.CodeConfigurationConflict},
		{"null schema", `null`, `"2.0.0"`, refusal.CodeConfigurationConflict},
		{"number version", `"foreign"`, `2`, refusal.CodeConfigurationConflict},
		{"object schema", `{}`, `"2.0.0"`, refusal.CodeConfigurationConflict},
		{"array version", `"foreign"`, `[]`, refusal.CodeConfigurationConflict},
		{"space schema", `" "`, `"2.0.0"`, refusal.CodeConfigurationConflict},
		{"control version", `"foreign"`, `"2.0.0\u0000"`, refusal.CodeConfigurationConflict},
	}
	for _, dispatch := range dispatches {
		for _, shape := range fields {
			t.Run(dispatch.name+"/"+shape.name, func(t *testing.T) {
				members := append([]string(nil), shape.members...)
				if dispatch.schema != "" {
					members = append(members, `"schema":`+dispatch.schema)
				}
				if dispatch.version != "" {
					members = append(members, `"schema_version":`+dispatch.version)
				}
				// Rotate both forward and reversed orders to exercise dispatch before
				// and after every non-dispatch member and each other.
				for direction := 0; direction < 2; direction++ {
					for shift := range members {
						ordered := append(append([]string(nil), members[shift:]...), members[:shift]...)
						input := "{" + strings.Join(ordered, ",") + "}"
						got, err := hosted.DecodeCarrier([]byte(input))
						if dispatch.name == "known" && shape.name == "complete" {
							if err != nil || got != carrier() {
								t.Fatalf("known carrier: %+v %v", got, err)
							}
							continue
						}
						requireCode(t, err, dispatch.code)
						if got != (hosted.Carrier{}) || strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "private.invalid") {
							t.Fatalf("unsafe refusal: %+v %v", got, err)
						}
					}
					for i, j := 0, len(members)-1; i < j; i, j = i+1, j-1 {
						members[i], members[j] = members[j], members[i]
					}
				}
			})
		}
	}
}

func TestCarrierLexicalChecksBeforeDispatch(t *testing.T) {
	data, _ := hosted.EncodeCarrier(carrier())
	future := strings.Replace(string(data), "1.0.0", "2.0.0", 1)
	for name, input := range map[string]string{
		"trailing object":   future + " {}",
		"trailing junk":     future + "x",
		"truncated":         future[:len(future)-1],
		"invalid UTF8":      future + string([]byte{0xff}),
		"oversized":         future + strings.Repeat(" ", 2049-len(future)),
		"duplicate":         strings.TrimSuffix(future, "}") + `,"ref":"CANARY"}`,
		"escaped duplicate": strings.TrimSuffix(future, "}") + `,"sch\u0065ma_version":"2.0.0"}`,
		"nested duplicate":  strings.TrimSuffix(future, "}") + `,"future":{"x":1,"\u0078":2}}`,
		"malformed nested":  strings.TrimSuffix(future, "}") + `,"future":[true,]}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := hosted.DecodeCarrier([]byte(input))
			requireCode(t, err, refusal.CodeConfigurationConflict)
			if got != (hosted.Carrier{}) || strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("unsafe refusal: %+v %v", got, err)
			}
		})
	}
}

func TestCarrierFutureLexicalDomain(t *testing.T) {
	cases := []struct {
		name, member string
		valid        bool
	}{
		{"high surrogate", `"future":"CANARY\ud800"`, false},
		{"low surrogate", `"future":"\udfff"`, false},
		{"high followed by scalar", `"future":"\ud800\u0041"`, false},
		{"reversed pair", `"future":"\udc00\ud800"`, false},
		{"two high surrogates", `"future":"\ud800\udbff"`, false},
		{"high followed by literal", `"future":"\ud800x"`, false},
		{"high followed by escaped slash", `"future":"\ud800\\udc00"`, false},
		{"top level key", `"CANARY\ud800":true`, false},
		{"nested key", `"future":{"\udc00":true}`, false},
		{"array string", `"future":[{"x":["\ud800"]}]`, false},
		{"pair then lone", `"future":"\ud800\udc00\ud800"`, false},
		{"truncated unicode escape", `"future":"\ud80"`, false},
		{"invalid unicode hex", `"future":"\ud80z"`, false},
		{"negative zero", `"future":-0`, false},
		{"fraction", `"future":0.5`, false},
		{"negative fraction", `"future":-0.5`, false},
		{"decimal lexeme", `"future":1.0`, false},
		{"exponent lexeme", `"future":1e0`, false},
		{"large exponent", `"future":1e999`, false},
		{"positive overflow", `"future":9007199254740992`, false},
		{"negative overflow", `"future":-9007199254740992`, false},
		{"integer overflow", `"future":9223372036854775808`, false},
		{"nested number", `"future":{"x":[true,{"y":-0}]}`, false},
		{"array fraction", `"future":[0,0.5]`, false},
		{"nested overflow", `"future":{"x":9007199254740992}`, false},
		{"literal replacement character", `"future":"�"`, true},
		{"escaped replacement character", `"future":"\ufffd"`, true},
		{"surrogate pair", `"future":"\ud800\udc00"`, true},
		{"uppercase pair", `"future":"\uDBFF\uDFFF"`, true},
		{"paired key", `"\ud83d\ude00":true`, true},
		{"nested unicode", `"future":{"\ufffd":["\ud83d\ude00","�"]}`, true},
		{"surrogate text", `"future":"\\ud800"`, true},
		{"escaped quote", `"future":"\"\\ud800"`, true},
		{"integer boundaries", `"future":[-9007199254740991,0,9007199254740991]`, true},
		{"nested integers", `"future":{"x":[true,null,{"y":-42}]}`, true},
	}
	dispatches := []struct{ name, schema, version string }{
		{"unknown schema", "foreign", hosted.SchemaVersion},
		{"unknown version", hosted.Schema, "2.0.0"},
		{"both unknown", "foreign", "2.0.0"},
	}
	for _, dispatch := range dispatches {
		for _, tc := range cases {
			t.Run(dispatch.name+"/"+tc.name, func(t *testing.T) {
				wantCode, wantDetail := refusal.CodeConfigurationConflict, "malformed network carrier"
				if tc.valid {
					wantCode, wantDetail = refusal.CodeScopeUnsupported, "unsupported carrier schema or version"
				}
				wantError := wantCode + ": network: " + wantDetail
				members := []string{`"schema":"` + dispatch.schema + `"`, `"schema_version":"` + dispatch.version + `"`, tc.member}
				for direction := 0; direction < 2; direction++ {
					for shift := range members {
						ordered := append(append([]string(nil), members[shift:]...), members[:shift]...)
						input := "{" + strings.Join(ordered, ",") + "}"
						got, err := hosted.DecodeCarrier([]byte(input))
						requireCode(t, err, wantCode)
						if got != (hosted.Carrier{}) || err.Error() != wantError {
							t.Fatalf("refusal: %+v %v; want zero carrier and %q", got, err, wantError)
						}
						var payload struct {
							Network *hosted.Carrier `json:"network"`
						}
						// Invalid escape syntax is rejected by the outer JSON decoder
						// before it can call Carrier.UnmarshalJSON.
						if json.Valid([]byte(input)) {
							err = json.Unmarshal([]byte(`{"network":`+input+`}`), &payload)
							requireCode(t, err, wantCode)
							if err.Error() != wantError || (payload.Network != nil && *payload.Network != (hosted.Carrier{})) {
								t.Fatalf("nested refusal: %+v %v", payload.Network, err)
							}
						}
					}
					members[0], members[2] = members[2], members[0]
				}
			})
		}
	}
}

func TestCarrierMalformedDispatchAPIs(t *testing.T) {
	for _, field := range []string{"schema", "schema_version"} {
		c := carrier()
		if field == "schema" {
			c.Schema = ""
		} else {
			c.SchemaVersion = ""
		}
		requireCode(t, c.Validate(), refusal.CodeConfigurationConflict)
		data, err := hosted.EncodeCarrier(c)
		requireCode(t, err, refusal.CodeConfigurationConflict)
		if data != nil {
			t.Fatal("malformed dispatch encoded")
		}
	}
	for _, version := range []string{`""`, `"2.0.0"`} {
		input := `{"network":{"schema":"` + hosted.Schema + `","schema_version":` + version + `,"future":true}}`
		var payload struct {
			Network *hosted.Carrier `json:"network"`
		}
		err := json.Unmarshal([]byte(input), &payload)
		want := refusal.CodeConfigurationConflict
		if version == `"2.0.0"` {
			want = refusal.CodeScopeUnsupported
		}
		requireCode(t, err, want)
		if payload.Network != nil && *payload.Network != (hosted.Carrier{}) {
			t.Fatal("partial nested carrier")
		}
	}
}

func TestCarrierByteLimit(t *testing.T) {
	const limit = 2048
	if hosted.MaxCarrierBytes != limit {
		t.Fatalf("published limit = %d; want %d", hosted.MaxCarrierBytes, limit)
	}
	data, err := hosted.EncodeCarrier(carrier())
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{limit, limit + 1} {
		input := append(append([]byte(nil), data...), strings.Repeat(" ", size-len(data))...)
		got, err := hosted.DecodeCarrier(input)
		if size == limit {
			if err != nil || got != carrier() {
				t.Fatalf("%d-byte carrier: %+v %v", size, got, err)
			}
		} else {
			requireCode(t, err, refusal.CodeConfigurationConflict)
			if got != (hosted.Carrier{}) {
				t.Fatalf("partial carrier: %+v", got)
			}
		}
	}
}

func FuzzCarrier(f *testing.F) {
	data, _ := hosted.EncodeCarrier(carrier())
	f.Add(data)
	f.Add([]byte("null"))
	f.Add([]byte(`{"ref":"a","ref":"b"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		c, err := hosted.DecodeCarrier(input)
		if err != nil {
			if _, ok := refusal.CodeOf(err); !ok {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		encoded, err := hosted.EncodeCarrier(c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := hosted.DecodeCarrier(encoded)
		if err != nil || got != c {
			t.Fatalf("round trip: %+v %v", got, err)
		}
	})
}
