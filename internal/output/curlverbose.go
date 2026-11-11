// curlverbose.go implements curl-style verbose (-v) output: the "* ..."
// informational lines, "> " request lines and "< " response lines that tools
// parsing `curl -v` output rely on.  See output.go for the main Output type.
package output

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// CurlInfo writes an informational "* " line (curl -v format).
func (o *Output) CurlInfo(format string, args ...any) {
	if !o.verbose {
		return
	}

	msg := fmt.Sprintf(format, args...)
	// Multi-line messages are all prefixed with "* " like curl does.
	for _, line := range strings.Split(strings.TrimSuffix(msg, "\n"), "\n") {
		_, _ = o.logFileWriter.WriteString("* " + line + "\n")
	}
}

// CurlRequest writes the request in "> " format (curl -v).  Includes the
// request line, headers in wire order and the terminating "> " blank line.
func (o *Output) CurlRequest(req *http.Request, headerOrder []string) {
	if !o.verbose {
		return
	}

	write := func(format string, args ...any) {
		_, _ = o.logFileWriter.WriteString(fmt.Sprintf(format, args...))
	}

	path := req.URL.RequestURI()
	write("> %s %s %s\n", req.Method, path, req.Proto)
	write("> Host: %s\n", req.Host)

	// Headers in the given wire order first, then whatever else the request
	// carries (alphabetically — deterministic).
	seen := map[string]bool{ "host": true }
	for _, raw := range headerOrder {
		name, value, _ := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		seen[strings.ToLower(name)] = true
		write("> %s: %s\n", name, strings.TrimSpace(value))
	}
	rest := map[string][]string{}
	for name, vals := range req.Header {
		if !seen[strings.ToLower(name)] {
			rest[name] = vals
		}
	}
	for _, name := range sortedHeaderNames(rest) {
		write("> %s: %s\n", name, rest[name][0])
	}

	write("> \n")
}

// CurlResponse writes the response status line and headers in "< " format
// (curl -v), ending with the "< " blank line.
func (o *Output) CurlResponse(resp *http.Response) {
	if !o.verbose {
		return
	}

	write := func(format string, args ...any) {
		_, _ = o.logFileWriter.WriteString(fmt.Sprintf(format, args...))
	}

	write("< %s %s\n", resp.Proto, resp.Status)
	for _, name := range sortedHeaderNames(resp.Header) {
		// ":status" is folded into the status line above; skip pseudo-headers
		// like curl does.
		if strings.HasPrefix(name, ":") {
			continue
		}
		for _, v := range resp.Header[name] {
			write("< %s: %s\n", name, v)
		}
	}
	write("< \n")
}

// sortedHeaderNames returns the header names sorted alphabetically.
func sortedHeaderNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}
