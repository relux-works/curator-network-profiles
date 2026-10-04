// SPDX-License-Identifier: Apache-2.0

// Package hosted supplies the network boundary for a process-creating session
// host. It never starts processes or consults the process environment.
package hosted

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/curator-network-profiles/pkg/netprofile"
	"github.com/relux-works/curator-network-profiles/pkg/refusal"
	"github.com/relux-works/curator-network-profiles/pkg/resolve"
)

const (
	Schema        = "urn:relux:task-board:network-binding"
	SchemaVersion = "1.0.0"
	// MaxCarrierBytes bounds the complete JSON value, including whitespace.
	MaxCarrierBytes = 2048
)

type Origin string

const (
	OriginExplicit  Origin = "explicit"
	OriginInherited Origin = "inherited"
	OriginRuntime   Origin = "runtime"
	OriginProject   Origin = "project"
	OriginOperator  Origin = "operator"
)

// Carrier is the credential-free network member of a hosted launch payload.
// The outer decoder handles network:null as unmanaged; this type is managed.
type Carrier struct {
	Schema         string `json:"schema"`
	SchemaVersion  string `json:"schema_version"`
	Ref            string `json:"ref"`
	Origin         Origin `json:"origin"`
	ExpectedDigest string `json:"expected_digest"`
}

// UnmarshalJSON also enforces the closed decoder when Carrier is nested in a
// payload. An outer *Carrier may represent network:null as nil.
func (c *Carrier) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeCarrier(data)
	if err != nil {
		return err
	}
	*c = decoded
	return nil
}

// MarshalJSON validates and uses the same canonical encoding as EncodeCarrier.
func (c Carrier) MarshalJSON() ([]byte, error) { return EncodeCarrier(c) }

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var reservedRefRE = regexp.MustCompile(`^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)`)

// Validate enforces both netprofile names and the pinned Curator identifier
// rules (no trailing dot or DOS device name), with no normalization.
func (c Carrier) Validate() error {
	if err := validateDispatch(c.Schema, c.SchemaVersion); err != nil {
		return err
	}
	if netprofile.ValidateName(c.Ref) != nil || strings.HasSuffix(c.Ref, ".") || reservedRefRE.MatchString(c.Ref) {
		return invalidCarrier("invalid profile reference")
	}
	if _, ok := recordOrigin(c.Origin); !ok {
		return invalidCarrier("invalid selection origin")
	}
	if !digestRE.MatchString(c.ExpectedDigest) {
		return invalidCarrier("invalid expected digest")
	}
	return nil
}

// DecodeCarrier checks bounded lexical validity before schema/version dispatch,
// then enforces the recognized schema's five required string members. Unsupported
// identifiers refuse before shape checks. Duplicates (including escaped keys),
// trailing input, invalid Unicode and numbers outside the integer lexical domain
// always refuse as malformed. Diagnostics never include input. Use this function
// rather than json.Unmarshal.
func DecodeCarrier(data []byte) (Carrier, error) {
	fail := func() (Carrier, error) { return Carrier{}, invalidCarrier("malformed network carrier") }
	if len(data) > MaxCarrierBytes || !utf8.Valid(data) || !validCarrierStringEscapes(data) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return fail()
	}
	values := make(map[string]any, 5)
	for d.More() {
		tok, err = d.Token()
		if err != nil {
			return fail()
		}
		key, ok := tok.(string)
		if !ok {
			return fail()
		}
		if _, exists := values[key]; exists {
			return fail()
		}
		value, err := carrierValue(d)
		if err != nil {
			return fail()
		}
		values[key] = value
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') {
		return fail()
	}
	if _, err = d.Token(); err != io.EOF {
		return fail()
	}
	schema, schemaOK := values["schema"].(string)
	version, versionOK := values["schema_version"].(string)
	if !schemaOK || !versionOK {
		return fail()
	}
	if err := validateDispatch(schema, version); err != nil {
		return Carrier{}, err
	}
	if len(values) != 5 {
		return fail()
	}
	for _, key := range []string{"schema", "schema_version", "ref", "origin", "expected_digest"} {
		if _, ok := values[key].(string); !ok {
			return fail()
		}
	}
	c := Carrier{schema, version, values["ref"].(string), Origin(values["origin"].(string)), values["expected_digest"].(string)}
	if err := c.Validate(); err != nil {
		return Carrier{}, err
	}
	return c, nil
}

// validCarrierStringEscapes checks raw strings before encoding/json replaces
// lone UTF-16 surrogates with U+FFFD. Actual U+FFFD and paired surrogates are valid.
// JSON syntax, including other escapes, is checked by the token decoder.
func validCarrierStringEscapes(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		unit, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		switch {
		case unit >= 0xdc00 && unit <= 0xdfff:
			return false
		case unit >= 0xd800 && unit <= 0xdbff:
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inString
}

func validateDispatch(schema, version string) error {
	for _, identifier := range []string{schema, version} {
		if identifier == "" {
			return invalidCarrier("malformed carrier schema or version")
		}
		for _, r := range identifier {
			if r < '!' || r > '~' {
				return invalidCarrier("malformed carrier schema or version")
			}
		}
	}
	if schema != Schema || version != SchemaVersion {
		return refusal.New(refusal.CodeScopeUnsupported, "network", "unsupported carrier schema or version")
	}
	return nil
}

// carrierValue consumes a complete JSON value without interpreting its shape.
// It checks duplicates and integer lexemes at every depth, including future fields.
// Containers are represented by their delimiter because only strings are used
// after dispatch. The complete input is bounded before recursive parsing.
func carrierValue(d *json.Decoder) (any, error) {
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	if number, ok := tok.(json.Number); ok {
		const maxInteger = 9007199254740991
		value, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil || number == "-0" || value < -maxInteger || value > maxInteger {
			return nil, invalidCarrier("malformed network carrier")
		}
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	end := json.Delim(']')
	if delim == '{' {
		end = '}'
	} else if delim != '[' {
		return nil, invalidCarrier("malformed network carrier")
	}
	seen := make(map[string]bool)
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return nil, invalidCarrier("malformed network carrier")
			}
			seen[name] = true
		}
		if _, err := carrierValue(d); err != nil {
			return nil, err
		}
	}
	if tok, err := d.Token(); err != nil || tok != end {
		return nil, invalidCarrier("malformed network carrier")
	}
	return delim, nil
}

// EncodeCarrier returns validated, compact JSON with keys in byte order and no
// newline. The encoder is canonical regardless of the input JSON member order.
func EncodeCarrier(c Carrier) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ExpectedDigest string `json:"expected_digest"`
		Origin         Origin `json:"origin"`
		Ref            string `json:"ref"`
		Schema         string `json:"schema"`
		SchemaVersion  string `json:"schema_version"`
	}{c.ExpectedDigest, c.Origin, c.Ref, c.Schema, c.SchemaVersion})
}

func invalidCarrier(detail string) error {
	return refusal.New(refusal.CodeConfigurationConflict, "network", detail)
}

func recordOrigin(o Origin) (resolve.Origin, bool) {
	switch o {
	case OriginExplicit:
		return resolve.OriginExplicit, true
	case OriginInherited:
		return resolve.OriginInherited, true
	case OriginRuntime:
		return resolve.OriginRuntimeDefault, true
	case OriginProject:
		return resolve.OriginProjectDefault, true
	case OriginOperator:
		return resolve.OriginOperatorDefault, true
	default:
		return "", false
	}
}
