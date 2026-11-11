// Package client is responsible for creating HTTP client and request.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ameshkov/gocurl/internal/client/tlsh2"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/ameshkov/gocurl/internal/profile"
	utls "github.com/refraction-networking/utls"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// Transport is the interface that's used for sending/receiving HTTP requests.
type Transport interface {
	http.RoundTripper

	// Conn returns the last established connection using this transport.
	Conn() (conn net.Conn)
}

// transport is a wrapper over regular http.RoundTripper that is used to add
// additional logic on top of RoundTrip.
type transport struct {
	d    *clientDialer
	base http.RoundTripper
}

// type check
var _ Transport = (*transport)(nil)

// Conn returns the last established connection using this transport.
func (t *transport) Conn() (conn net.Conn) {
	return t.d.conn
}

// RoundTrip implements the http.RoundTripper interface for *transport.
//
// TODO(ameshkov): dial explicitly here and then check negotiation proto.
// This approach will make it easier to handle protocols negotiation.
func (t *transport) RoundTrip(r *http.Request) (resp *http.Response, err error) {
	resp, err = t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	// Make sure that resp.TLS field is set regardless of what protocol was
	// used.  This is important for ECH-enabled connections as crypto/tls is
	// not used there and the regular http.Transport will not set the TLS field.
	type tlsConnectionStater interface {
		ConnectionState() tls.ConnectionState
	}
	if c, ok := t.d.conn.(tlsConnectionStater); ok {
		state := c.ConnectionState()
		resp.TLS = &state
	}

	return resp, err
}

// NewTransport creates a new http.RoundTripper that will be used for making
// the request.
func NewTransport(cfg *config.Config, out *output.Output) (rt Transport, err error) {
	// If OHTTP is enabled, use the oblivious HTTP transport.
	if cfg.OHTTPGatewayURL != nil && cfg.OHTTPKeysURL != nil {
		return newObliviousHTTPTransport(cfg, out)
	}

	hostname := cfg.RequestURL.Hostname()
	d, err := newDialer(hostname, cfg, out)
	if err != nil {
		return nil, err
	}

	bt, err := createHTTPTransport(d, cfg)
	if err != nil {
		return nil, err
	}

	return &transport{d: d, base: bt}, nil
}

// createHTTPTransport creates http.RoundTripper that will be used by the
// *http.Client. Depending on the configuration it may create an H1, H2 or H3
// transport.
func createHTTPTransport(
	d *clientDialer,
	cfg *config.Config,
) (rt http.RoundTripper, err error) {
	if cfg.ForceHTTP3 {
		return createH3Transport(d)
	}

	if cfg.ForceHTTP2 {
		return createH2Transport(d)
	}

	return createH12Transport(d)
}

// createH3Transport creates an http.RoundTripper to be used in HTTP/3 client.
func createH3Transport(d *clientDialer) (rt http.RoundTripper, err error) {
	return &http3.Transport{
		DisableCompression: true,
		Dial:               d.DialQUIC,
	}, nil
}

// h2Transport is an http.RoundTripper implementation that forcibly use
// http2.Transport.
type h2Transport struct {
	d *clientDialer
}

// type check
var _ http.RoundTripper = (*h2Transport)(nil)

// RoundTrip implements the http.RoundTripper for *h2Transport.
func (t *h2Transport) RoundTrip(r *http.Request) (resp *http.Response, err error) {
	port := r.URL.Port()
	if port == "" {
		switch r.URL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	addr := net.JoinHostPort(r.URL.Hostname(), port)
	conn, err := t.d.DialTLSContext(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}

	tr := &http2.Transport{DisableCompression: true}
	clientConn, err := tr.NewClientConn(conn)
	if err != nil {
		return nil, err
	}

	return clientConn.RoundTrip(r)
}

// createH2Transport creates a http.RoundTripper to be used specifically with
// HTTP/2.  This option is required when using --ech option as in this case
// we don't use *tls.Conn and it does not work well with the regular transport.
func createH2Transport(d *clientDialer) (rt http.RoundTripper, err error) {
	return &h2Transport{d: d}, nil
}

// createH12Transport creates a http.RoundTripper to be used in HTTP/1.1 or
// HTTP/2 client.
//
// Phase 0 spike: the TLS layer is now uTLS, whose conn is not *tls.Conn.
// stdlib net/http only upgrades to HTTP/2 via TLSNextProto when the conn is
// exactly *tls.Conn, so instead we dial first, check the negotiated ALPN
// protocol ourselves and route to the x/net http2.Transport (which accepts
// any conn with a ConnectionState method) or fall back to HTTP/1.1.
func createH12Transport(d *clientDialer) (rt http.RoundTripper, err error) {
	return &uTransport{d: d}, nil
}

// uTransport is a RoundTripper that dials TLS with uTLS and routes the
// connection to HTTP/2 or HTTP/1.1 based on the negotiated ALPN protocol.
type uTransport struct {
	d *clientDialer
}

// type check
var _ http.RoundTripper = (*uTransport)(nil)

// RoundTrip implements http.RoundTripper for *uTransport.
func (t *uTransport) RoundTrip(r *http.Request) (resp *http.Response, err error) {
	scheme := r.URL.Scheme
	if scheme != "https" {
		// Plain HTTP: use the default transport path.
		return t.httpBaseRoundTrip(r)
	}

	resp, err = t.roundTripTLS(r)
	if err != nil {
		return nil, err
	}

	// -L/--location: follow redirects on the TLS path as well.
	if cfg := t.d.cfg; cfg.Location && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return followRedirects(t, r, resp)
	}

	return resp, err
}

// roundTripTLS performs the request over a uTLS connection.
func (t *uTransport) roundTripTLS(r *http.Request) (*http.Response, error) {
	port := r.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(r.URL.Hostname(), port)

	conn, err := t.d.DialTLSContext(r.Context(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialTLS %s: %w", addr, err)
	}

	proto := ""
	if u, ok := conn.(*utls.UConn); ok {
		// uTLS defines its own ConnectionState type, which does not match
		// the stdlib interface assertion below.
		proto = u.ConnectionState().NegotiatedProtocol
	} else if state, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		proto = state.ConnectionState().NegotiatedProtocol
	}

	if proto == "h2" {
		if u, ok := conn.(*utls.UConn); ok {
			st := u.ConnectionState()
			t.d.out.CurlInfo("Connected to %s (%s) port %s", r.URL.Hostname(), conn.RemoteAddr(), portOr443(r.URL))
			t.d.out.CurlInfo("ALPN: server accepted h2 (%s)", tls.VersionName(uint16(st.Version)))
		}

		// If the active profile carries an HTTP/2 fingerprint, use the
		// fingerprint-exact single-request framer instead of the standard
		// transport (whose SETTINGS/window/header order is fixed).
		if fp := t.h2Fingerprint(); fp != nil {
			t.d.out.CurlInfo("using HTTP/2 with profile fingerprint")
			return t.roundTripH2Fingerprint(conn, r, fp)
		}

		t.d.out.CurlInfo("using HTTP/2")
		tr := &http2.Transport{DisableCompression: true}
		clientConn, err := tr.NewClientConn(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}

		return clientConn.RoundTrip(r)
	}

	// HTTP/1.1 over the uTLS connection.
	t.d.out.CurlInfo("using HTTP/1.1")
	return h1RoundTrip(conn, r)
}

// portOr443 returns the URL's port as a string, defaulting to 443.
func portOr443(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}

	return "443"
}

// h2Fingerprint returns the HTTP/2 fingerprint of the active profile, or nil
// when impersonation is off or the profile has no H2 section.
func (t *uTransport) h2Fingerprint() *profile.H2FingerprintSpec {
	if t.d.cfg.Impersonate == "" || t.d.cfg.Impersonate == "none" {
		return nil
	}

	prof, err := profile.Get(t.d.cfg.Impersonate)
	if err != nil {
		return nil
	}

	return prof.H2Fingerprint()
}

// profileDefaultHeaderOrder returns the active profile's default header
// strings ("name: value", declared order) or nil when impersonation is off.
func (t *uTransport) profileDefaultHeaderOrder() []string {
	prof, err := profile.Get(t.d.cfg.Impersonate)
	if err != nil || prof == nil || prof.HTTP == nil {
		return nil
	}

	return prof.HTTP.DefaultHeaders
}

// roundTripH2Fingerprint sends the request over the established TLS conn
// using the fingerprint-exact framer and converts the response back to
// *http.Response.
func (t *uTransport) roundTripH2Fingerprint(conn net.Conn, r *http.Request, fp *profile.H2FingerprintSpec) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	fields := make([]tlsh2.HeaderField, 0, len(r.Header))
	// Header wire order: user -H/--header order first, then the profile's
	// default headers in their declared order, then any remaining headers
	// the request carries (sorted for determinism — Go map iteration order
	// must never reach the wire).
	seen := map[string]bool{}
	addField := func(raw string) {
		name, value, _ := strings.Cut(raw, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		fields = append(fields, tlsh2.HeaderField{Name: name, Value: strings.TrimSpace(value)})
	}
	for _, raw := range t.d.cfg.RawHeaders {
		addField(raw)
	}
	for _, raw := range t.profileDefaultHeaderOrder() {
		addField(raw)
	}
	// Anything the request still carries (e.g. headers added programmatically
	// like Content-Type from -d) in deterministic order.
	var rest []string
	for name := range r.Header {
		if !seen[strings.ToLower(name)] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		fields = append(fields, tlsh2.HeaderField{Name: strings.ToLower(name), Value: r.Header.Get(name)})
	}

	h2req := &tlsh2.Request{
		Method:       r.Method,
		Scheme:       "https",
		Authority:    r.Host,
		Path:         r.URL.RequestURI(),
		HeaderFields: fields,
		Body:         body,
	}

	wireFp := &tlsh2.Fingerprint{
		ConnWindowUpdate:  fp.ConnWindowUpdate,
		PseudoHeaderOrder: fp.PseudoHeaderOrder,
	}
	for _, s := range fp.Settings {
		wireFp.Settings = append(wireFp.Settings, tlsh2.Setting{ID: s.ID, Val: s.Val})
	}

	h2resp, err := tlsh2.Do(r.Context(), conn, wireFp, h2req)
	if err != nil {
		return nil, err
	}

	resp := &http.Response{
		StatusCode: h2resp.StatusCode,
		Status:     fmt.Sprintf("%d %s", h2resp.StatusCode, http.StatusText(h2resp.StatusCode)),
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     make(http.Header, len(h2resp.HeaderFields)),
		Body:       io.NopCloser(bytes.NewReader(h2resp.Body)),
		ContentLength: int64(len(h2resp.Body)),
		Request:    r,
	}
	for _, f := range h2resp.HeaderFields {
		resp.Header.Add(f.Name, f.Value)
	}

	return resp, nil
}

// maxRedirects is the redirect limit matching curl's default (-L follows up
// to 10 hops... actually 50; we use curl-impersonate's default).
const maxRedirects = 10

// followRedirects follows 3xx responses by re-issuing the request to the
// Location target.  Only https and http schemes are supported.  Redirects
// after POST downgrade to GET like curl does for 303 (and for 301/302 with a
// POST body, curl historically does the same unless --post301 etc).
func followRedirects(t *uTransport, firstReq *http.Request, firstResp *http.Response) (*http.Response, error) {
	resp := firstResp
	req := firstReq

	for redirects := 0; redirects < maxRedirects; redirects++ {
		loc := resp.Header.Get("Location")
		resp.Body.Close()

		if loc == "" {
			return nil, fmt.Errorf("redirect with no Location header (status %d)", resp.StatusCode)
		}

		ref, err := url.Parse(loc)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect Location %q: %w", loc, err)
		}

		newURL := req.URL.ResolveReference(ref)
		if newURL.Scheme != "http" && newURL.Scheme != "https" {
			return nil, fmt.Errorf("redirect to unsupported scheme %s", newURL.Scheme)
		}

		newReq := req.Clone(req.Context())
		newReq.URL = newURL
		newReq.Host = newURL.Host
		// Downgrade to GET on redirects when there was a body.
		if req.Method != http.MethodHead && req.Body != nil {
			newReq.Method = http.MethodGet
			newReq.Body = nil
			newReq.ContentLength = 0
		}

		if newURL.Scheme != "https" {
			resp, err = t.httpBaseRoundTrip(newReq)
		} else {
			resp, err = t.roundTripTLS(newReq)
		}
		if err != nil {
			return nil, err
		}

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, nil
		}
	}

	resp.Body.Close()

	return nil, fmt.Errorf("too many redirects (limit %d)", maxRedirects)
}

// httpBaseRoundTrip performs a plain HTTP request using the client dialer
// (which applies proxy/connect-to/resolve logic to the TCP dial).
func (t *uTransport) httpBaseRoundTrip(r *http.Request) (*http.Response, error) {
	tr := &http.Transport{
		DisableCompression: true,
		DisableKeepAlives:  true,
		DialContext:        t.d.DialContext,
	}

	return tr.RoundTrip(r)
}

// h1RoundConn is a net.Conn wrapper that reuses an already-established TLS
// connection with an http.Transport.
type h1RoundConn struct {
	net.Conn
}

// RoundTrip performs an HTTP/1.1 request over the pre-established TLS conn.
func h1RoundTrip(conn net.Conn, r *http.Request) (*http.Response, error) {
	tr := &http.Transport{
		DisableCompression: true,
		DisableKeepAlives:  true,
		// Must hand the conn over via DialTLSContext: for https URLs the
		// transport wraps DialContext conns in its own tls.Client, which
		// would double the TLS layer.
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}

	resp, err := tr.RoundTrip(r)
	if err != nil {
		conn.Close()
	}

	return resp, err
}

// getMethod returns HTTP method depending on the arguments.
func getMethod(cfg *config.Config) (method string) {
	if cfg.Method != "" {
		method = cfg.Method
	} else if cfg.Head {
		method = http.MethodHead
	} else if cfg.Data != "" {
		method = http.MethodPost
	} else {
		method = http.MethodGet
	}

	return method
}
