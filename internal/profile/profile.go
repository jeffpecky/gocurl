// Package profile holds the impersonation profile registry: named bundles of
// TLS (and later HTTP/2) parameters that make this client fingerprint like a
// specific browser version.
package profile

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"

	utls "github.com/refraction-networking/utls"
)

//go:embed profiles/*.json
var profilesFS embed.FS

// Profile is a named impersonation profile.
type Profile struct {
	// Name is the profile identifier passed to --impersonate, e.g.
	// "chrome-133".
	Name string `json:"name"`

	// Browser is the human-readable browser family.
	Browser string `json:"browser"`

	// TLS is the TLS fingerprint section: the uTLS ClientHello preset id and
	// the ALPN list the browser offers.
	TLS TLSProfile `json:"tls"`

	// H2 is the HTTP/2 fingerprint section (SETTINGS/frame order).
	H2 *H2Profile `json:"h2,omitempty"`

	// HTTP is the application-level HTTP fingerprint section: the User-Agent
	// and default request headers the browser sends.  When impersonation is
	// active, these are used as request defaults (explicit -H flags and
	// -A/-e win).
	HTTP *HTTPProfile `json:"http,omitempty"`

	// Default marks the profile used when --impersonate is omitted.
	Default bool `json:"default"`

	// Fingerprints are the declared fingerprint hashes of this profile,
	// verified by the selftest (selftest/verify.go).  Values may be a single
	// hash or, for profiles whose preset flaps between two valid wire states
	// across handshakes (e.g. uTLS's Chrome 120 conditional ALPS), a list of
	// acceptable hashes.  An empty map skips verification (e.g. for stale or
	// experimental profiles).
	Fingerprints map[string]FingerprintValue `json:"fingerprints,omitempty"`
}

// TLSProfile is the TLS section of a profile.
type TLSProfile struct {
	// ClientHelloID is the uTLS preset name, e.g. "HelloChrome_133".  Empty
	// string maps to uTLS's HelloChrome_Auto (the newest Chrome preset).
	ClientHelloID string `json:"client_hello_id"`

	// ALPN is the protocol list offered in the ClientHello.  It is used to
	// build the connection's ALPN unless the user forces a protocol.
	ALPN []string `json:"alpn"`
}

// H2Profile is the HTTP/2 section of a profile.
type H2Profile struct {
	// Settings is the ordered list of SETTINGS frame entries sent by the
	// browser right after the connection preface, e.g. [{"id":1,"val":65536},
	// ...].
	Settings []H2Setting `json:"settings"`

	// WindowUpdate is the connection-level WINDOW_UPDATE increment (0 = no
	// frame).
	WindowUpdate uint32 `json:"window_update,omitempty"`

	// PseudoHeaderOrder is the wire order of request pseudo-headers as single
	// letters: m(:method), s(:scheme), a(:authority), p(:path).  Browsers
	// send "amsp"-style orders; curl-impersonate profiles use the same.
	PseudoHeaderOrder string `json:"pseudo_header_order"`
}

// H2Setting is a single HTTP/2 SETTINGS entry.
type H2Setting struct {
	ID  uint16 `json:"id"`
	Val uint32 `json:"val"`
}

// HTTPProfile is the application-level HTTP section of a profile.
type HTTPProfile struct {
	// UserAgent is the User-Agent the browser sends (also used for HTTP/1.1
	// requests; the TLS/H2 layers don't depend on it).
	UserAgent string `json:"user_agent"`

	// DefaultHeaders are the browser's default request headers (name: value
	// strings, in wire order).  User-supplied -H headers win; these fill in
	// the ones the user didn't specify.
	DefaultHeaders []string `json:"default_headers,omitempty"`
}

// registry is the parsed set of all embedded profiles, keyed by name.
var registry map[string]*Profile

func init() {
	registry = map[string]*Profile{}

	entries, err := profilesFS.ReadDir("profiles")
	if err != nil {
		panic(fmt.Sprintf("profile: reading embedded profiles: %v", err))
	}

	for _, e := range entries {
		data, err := profilesFS.ReadFile("profiles/" + e.Name())
		if err != nil {
			panic(fmt.Sprintf("profile: reading %s: %v", e.Name(), err))
		}

		var p Profile
		if err := json.Unmarshal(data, &p); err != nil {
			panic(fmt.Sprintf("profile: parsing %s: %v", e.Name(), err))
		}

		registry[p.Name] = &p
	}
}

// DefaultProfileName is the name of the profile used when --impersonate is
// not specified.
func DefaultProfileName() (name string, err error) {
	for _, p := range registry {
		if p.Default {
			return p.Name, nil
		}
	}

	return "", fmt.Errorf("no profile marked default in the registry")
}

// Get returns the named profile or an error listing valid names.
func Get(name string) (p *Profile, err error) {
	if name == "" || name == "none" {
		return nil, nil
	}

	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown impersonate profile %q, available: %v", name, Names())
	}

	return p, nil
}

// Names returns the sorted list of registered profile names.
func Names() (names []string) {
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

// FingerprintValue is a declared fingerprint: either a single hash or a list
// of acceptable hashes (for presets with more than one valid wire state).
type FingerprintValue struct {
	// Any is the list of acceptable hashes; any match passes.
	Any []string
}

// UnmarshalJSON accepts both "hash" and ["hash1","hash2"] forms.
func (f *FingerprintValue) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		f.Any = []string{single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(b, &multiple); err != nil {
		return err
	}
	f.Any = multiple

	return nil
}

// MarshalJSON writes the value back in its minimal form.
func (f FingerprintValue) MarshalJSON() ([]byte, error) {
	if len(f.Any) == 1 {
		return json.Marshal(f.Any[0])
	}

	return json.Marshal(f.Any)
}

// H2Fingerprint converts the profile's HTTP/2 section into the wire-level
// fingerprint for tlsh2.  A profile without an H2 section yields nil, meaning
// "use the standard Go transport" (no H2 fingerprint control).
func (p *Profile) H2Fingerprint() *H2FingerprintSpec {
	if p.H2 == nil {
		return nil
	}

	fp := &H2FingerprintSpec{
		ConnWindowUpdate:  p.H2.WindowUpdate,
		PseudoHeaderOrder: p.H2.PseudoHeaderOrder,
	}
	for _, s := range p.H2.Settings {
		fp.Settings = append(fp.Settings, H2SettingWire{ID: s.ID, Val: s.Val})
	}

	return fp
}

// H2FingerprintSpec is the wire-level HTTP/2 fingerprint (decoupled from the
// JSON shape).
type H2FingerprintSpec struct {
	Settings          []H2SettingWire
	ConnWindowUpdate  uint32
	PseudoHeaderOrder string
}

// H2SettingWire is one SETTINGS entry on the wire.
type H2SettingWire struct {
	ID  uint16
	Val uint32
}

// ClientHelloID maps the profile's TLS.ClientHelloID string to a uTLS
// ClientHelloID.  Unknown strings error.
func (p *Profile) ClientHelloID() (id utls.ClientHelloID, err error) {
	switch p.TLS.ClientHelloID {
	case "", "HelloChrome_Auto":
		return utls.HelloChrome_Auto, nil
	case "HelloChrome_120":
		return utls.HelloChrome_120, nil
	case "HelloChrome_120_PQ":
		return utls.HelloChrome_120_PQ, nil
	case "HelloChrome_131":
		return utls.HelloChrome_131, nil
	case "HelloChrome_133":
		return utls.HelloChrome_133, nil
	case "HelloFirefox_105":
		return utls.HelloFirefox_105, nil
	case "HelloFirefox_120":
		return utls.HelloFirefox_120, nil
	case "HelloSafari_16_0":
		return utls.HelloSafari_16_0, nil
	case "HelloIOS_14":
		return utls.HelloIOS_14, nil
	case "HelloEdge_85":
		return utls.HelloEdge_85, nil
	}

	return id, fmt.Errorf("profile %s: unknown client_hello_id %q", p.Name, p.TLS.ClientHelloID)
}
