package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ameshkov/gocurl/internal/appversion"
	"github.com/ameshkov/gocurl/internal/client/websocket"
	"github.com/ameshkov/gocurl/internal/config"
)

// NewRequest creates a new *http.Request based on *cmd.Options.
func NewRequest(cfg *config.Config) (req *http.Request, err error) {
	var bodyStream io.Reader

	// Do not add body for WebSocket requests as in this case --data is handled
	// differently, and it is sent after the handshake.
	if !websocket.IsWebSocket(cfg.RequestURL) {
		bodyStream, err = createBody(cfg)
		if err != nil {
			return nil, err
		}
	}

	// -G/--get: move the data into the URL query string and use GET.
	method := getMethod(cfg)
	if cfg.Get && !websocket.IsWebSocket(cfg.RequestURL) {
		method = http.MethodGet

		u := *cfg.RequestURL
		if cfg.Data != "" {
			q := u.Query()
			for _, kv := range strings.Split(cfg.Data, "&") {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) == 2 {
					q.Add(parts[0], parts[1])
				}
			}
			u.RawQuery = q.Encode()
		}
		req, err = http.NewRequest(method, u.String(), bodyStream)
	} else {
		req, err = http.NewRequest(method, cfg.RequestURL.String(), bodyStream)
	}
	if err != nil {
		return nil, err
	}

	addHeaders(req, cfg)
	addBodyHeaders(req, cfg)

	// -u/--user: basic authentication.
	if cfg.User != "" {
		user, pass, _ := strings.Cut(cfg.User, ":")
		req.SetBasicAuth(user, pass)
	}

	// Only set default User-Agent if it was not set by the user.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", fmt.Sprintf("gocurl/%s", appversion.Version()))
	}

	if ur := websocket.UpgradeWebSocket(req); ur != nil {
		req = ur
	}

	return req, err
}

// createBody creates body stream if it's required by the command-line
// arguments.  Priority: --data-raw, --data-binary, --data.
func createBody(cfg *config.Config) (body io.Reader, err error) {
	data := cfg.Data
	if cfg.DataRaw != "" {
		data = cfg.DataRaw
	} else if cfg.DataBinary != "" {
		data = cfg.DataBinary
	}

	if data == "" {
		return nil, nil
	}

	return bytes.NewBufferString(data), nil
}

// bodyData returns the effective request body data (--data/--data-raw/
// --data-binary).
func bodyData(cfg *config.Config) (data string) {
	if cfg.DataRaw != "" {
		return cfg.DataRaw
	}
	if cfg.DataBinary != "" {
		return cfg.DataBinary
	}

	return cfg.Data
}

// addBodyHeaders adds necessary HTTP headers if they're required by the
// command-line arguments. For instance, -d/--data requires adding the
// Content-Type: application/x-www-form-urlencoded header.
func addBodyHeaders(req *http.Request, cfg *config.Config) {
	data := bodyData(cfg)
	if data != "" && !websocket.IsWebSocket(cfg.RequestURL) {
		if req.Header.Get("Content-Type") == "" && cfg.DataBinary == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	// --compressed: ask for a compressed response.
	if cfg.Compressed && req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	// -A/--user-agent and -e/--referer are shortcuts for -H.
	if cfg.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", cfg.UserAgent)
	}
	if cfg.Referer != "" && req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", cfg.Referer)
	}

	// -b/--cookie: name=value pairs are sent directly; a file is parsed.
	if cfg.Cookie != "" {
		if cookieHeader := parseCookieArg(cfg.Cookie); cookieHeader != "" {
			req.Header.Add("Cookie", cookieHeader)
		}
	}
}

// parseCookieArg handles -b/--cookie: if the argument looks like a file
// (starts with @ or contains no "=" and exists on disk), read "name=value"
// lines from it; otherwise treat it as literal cookie pairs.
func parseCookieArg(arg string) (cookieHeader string) {
	var pairs []string

	isFile := strings.HasPrefix(arg, "@")
	if !isFile && !strings.Contains(arg, "=") {
		isFile = true
	}

	if isFile {
		fname := strings.TrimPrefix(arg, "@")
		b, err := os.ReadFile(fname)
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Netscape cookie file format: domain \t flag \t path \t secure
			// \t expiry \t name \t value.
			fields := strings.Split(line, "\t")
			if len(fields) == 7 {
				pairs = append(pairs, fields[5]+"="+fields[6])
			} else {
				pairs = append(pairs, line)
			}
		}
	} else {
		pairs = append(pairs, arg)
	}

	return strings.Join(pairs, "; ")
}

// addHeaders adds HTTP headers that are specified in command-line arguments.
func addHeaders(req *http.Request, cfg *config.Config) {
	for k, l := range cfg.Headers {
		for _, v := range l {
			req.Header.Add(k, v)
		}
	}
}
