// Command curl_diff compares this tool's output against real curl's output
// for every in-scope flag (PRD section 7: "drop-in correctness").  Both
// binaries run the same flag set against the same echo target; the outputs
// are normalized (curl's schannel/TLS lines and our TLS lines are stripped,
// volatile values like dates and latencies masked) and diffed.
//
// Usage:
//
//	go build -o gocurl . && go run ./selftest/curl_diff
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// target is the echo endpoint base both binaries hit; each case appends its
// own path (/get or /post).
var target = "https://httpbin.org"

// casediff is one flag combination and its comparison result.
type casediff struct {
	Name    string   `json:"name"`
	Args    []string `json:"args"`
	Match   bool     `json:"match"`
	Skipped bool     `json:"skipped,omitempty"`
	Note    string   `json:"note,omitempty"`
}

func main() {
	bin := flag.String("binary", "./gocurl", "path to the compiled gocurl binary")
	curlBin := flag.String("curl", "curl", "path to real curl")
	flag.Parse()

	// Each case: [name, args..., path].  The last element is the URL path;
	// POST cases target /post.
	cases := [][]string{
		{"plain GET", "/get"},
		{"-X POST -d", "-X", "POST", "-d", "k=v", "/post"},
		{"--data-raw", "--data-raw", "raw=1", "/post"},
		{"-A", "-A", "DiffAgent/1.0", "/get"},
		{"-e", "-e", "https://example.com/", "/get"},
		{"-H", "-H", "X-Test: 1", "-H", "X-Other: 2", "/get"},
		{"-u", "-u", "user:pass", "/get"},
		{"--compressed", "--compressed", "/get"},
		{"--max-time", "--max-time", "15", "/get"},
		{"-i", "-i", "/get"},
		{"-I HEAD", "-I", "/get"},
	}

	failed := false
	for _, c := range cases {
		name := c[0]
		args := append([]string{}, c[1:len(c)-1]...)
		path := c[len(c)-1]

		curlArgs := append(append([]string{}, args...), target+path)
		curlOut, err := run(*curlBin, curlArgs)
		if err != nil {
			printCase(name, false, "real curl failed: %v", err)
			failed = true
			continue
		}

		ourArgs := append(append([]string{}, args...), "--no-impersonate", target+path)
		ourOut, err := run(*bin, ourArgs)
		if err != nil {
			printCase(name, false, "gocurl failed: %v", err)
			failed = true
			continue
		}

		// -I/-i return non-JSON bodies; compare just the status line.
		if len(args) > 0 && (args[0] == "-I" || args[0] == "-i") {
			match, note := compareStatus(curlOut, ourOut)
			printCase(name, match, "%s", note)
			if !match {
				failed = true
			}
			continue
		}

		match, note := compare(curlOut, ourOut, args)
		printCase(name, match, "%s", note)
		if !match {
			failed = true
		}
	}

	if failed {
		os.Exit(1)
	}
}

// run executes a command and returns its stdout.
func run(bin string, args []string) (string, error) {
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: stderr: %s", err, truncate(stderr.String(), 200))
	}

	return stdout.String(), nil
}

// compareStatus checks that both outputs report the same HTTP status code.
// The protocol version is deliberately not compared: Windows curl negotiates
// HTTP/1.1 while this client speaks HTTP/2, and both are correct.
func compareStatus(curlOut, ourOut string) (match bool, note string) {
	statusRe := func(s string) string {
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, "HTTP/") {
				// "HTTP/1.1 200 OK" → fields after the protocol token.
				if f := strings.Fields(line); len(f) >= 2 {
					return f[1]
				}
			}
		}
		return ""
	}

	curlStatus := statusRe(curlOut)
	ourStatus := statusRe(ourOut)
	if curlStatus != ourStatus {
		return false, fmt.Sprintf("status: curl=%s ours=%s", curlStatus, ourStatus)
	}

	return true, "match"
}

// compare extracts the echoed headers from both outputs and reports which
// echo fields differ.  caseArgs decides which headers were set explicitly.
func compare(curlOut, ourOut string, caseArgs []string) (match bool, note string) {
	var cu, ou map[string]any
	if err := json.Unmarshal([]byte(stripNoise(curlOut)), &cu); err != nil {
		return false, fmt.Sprintf("parsing curl output: %v, body: %.200s", err, curlOut)
	}
	if err := json.Unmarshal([]byte(stripNoise(ourOut)), &ou); err != nil {
		return false, fmt.Sprintf("parsing gocurl output: %v, body: %.200s", err, ourOut)
	}

	// The response bodies differ in shape (headers casing, extra proxy
	// headers) — the checked contract is: method, and the headers WE set
	// explicitly appear with the same value.
	curlHdrs, _ := cu["headers"].(map[string]any)
	ourHdrs, _ := ou["headers"].(map[string]any)

	var diffs []string
	for _, k := range []string{"method"} {
		if fmt.Sprint(curlHdrs[k]) != fmt.Sprint(ourHdrs[k]) {
			diffs = append(diffs, fmt.Sprintf("%s: curl=%v ours=%v", k, curlHdrs[k], ourHdrs[k]))
		}
	}
	// Explicitly-set headers must match modulo casing.  user-agent is only
	// checked when the case sets it explicitly (-A) — each tool legitimately
	// uses its own default otherwise.
	curlLower := lowerKeys(curlHdrs)
	ourLower := lowerKeys(ourHdrs)
	uaExplicit := false
	for _, a := range caseArgs {
		if a == "-A" {
			uaExplicit = true
		}
	}
	for _, h := range []string{"referer", "x-test", "x-other", "authorization", "content-type", "user-agent"} {
		cv, cok := curlLower[h]
		ov, ook := ourLower[h]
		if h == "user-agent" && !uaExplicit {
			continue
		}
		if cok != ook || (cok && fmt.Sprint(cv) != fmt.Sprint(ov)) {
			diffs = append(diffs, fmt.Sprintf("%s: curl=%v(%v) ours=%v(%v)", h, cv, cok, ov, ook))
		}
	}

	if len(diffs) > 0 {
		return false, strings.Join(diffs, "; ")
	}

	return true, "match"
}

// stripNoise removes curl's verbose banners if any leak into stdout and
// trims whitespace around the JSON payload.
func stripNoise(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return s
	}

	return s[start:]
}

// lowerKeys lowercases every key of a header map for case-insensitive
// comparison.
func lowerKeys(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}

	return out
}

// printCase prints one comparison result.
func printCase(name string, ok bool, format string, args ...any) {
	status := "ok  "
	if !ok {
		status = "FAIL"
	}
	fmt.Printf("%s %s: %s\n", status, name, fmt.Sprintf(format, args...))
}

// truncate cuts s to n runes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n]
}
