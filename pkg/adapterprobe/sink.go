// SPDX-License-Identifier: Apache-2.0
package adapterprobe

import (
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// sink is not exposed or started by the current probe. A supervisor must
// generate a fresh 256-bit per-probe secret and keep it out of observable argv,
// logs and operator state. Proxy Basic auth conveys it for HTTP and CONNECT.
// It is checked before recording anything. Recipe scope also excludes telemetry.
type sink struct {
	mu            sync.Mutex
	expected      Observation
	authorization string
	observed      []Observation
	seen          chan struct{}
}

func newSink(token string, expected Observation) (*sink, error) {
	if !digestRE.MatchString(token) || (expected.Kind != "CONNECT" && expected.Kind != "absolute-URI") || authority(expected.Target, "") != expected.Target || expected.Target == "" {
		return nil, &Unsupported{Reason: "invalid_sink"}
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("probe:"+token))
	return &sink{expected: expected, authorization: auth, seen: make(chan struct{}, 1)}, nil
}
func (s *sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	if s.authorization == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(s.authorization)) != 1 {
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	var kind, target string
	if r.Method == http.MethodConnect {
		kind, target = "CONNECT", authority(r.RequestURI, "")
	} else if r.URL.IsAbs() && (r.URL.Scheme == "http" || r.URL.Scheme == "https") {
		port := "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
		kind, target = "absolute-URI", authority(r.URL.Host, port)
	}
	if (Observation{Kind: kind, Target: target}) == s.expected {
		s.mu.Lock()
		if len(s.observed) < 16 {
			s.observed = append(s.observed, s.expected)
		}
		s.mu.Unlock()
		select {
		case s.seen <- struct{}{}:
		default:
		}
	}
	// The handler does not inspect or retain bodies. net/http may buffer/discard
	// input while closing; neither the sink nor any transport forwards it.
	w.WriteHeader(http.StatusBadGateway)
}
func (s *sink) observations() []Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Observation(nil), s.observed...)
}
func authority(raw, defaultPort string) string {
	u, err := url.Parse("http://" + raw)
	if err != nil || u.User != nil || u.Host != raw || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return ""
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = defaultPort
	}
	n, err := strconv.Atoi(port)
	if host == "" || err != nil || n < 1 || n > 65535 || len(host) > 253 {
		return ""
	}
	if net.ParseIP(host) == nil {
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return ""
			}
		}
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(n))
}
