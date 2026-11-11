// Command selftest verifies that the live fingerprints of every declared
// profile still match the profile's declared JA3/JA4/Akamai hashes.  It is
// the CI gate from the PRD's Phase 4: a profile whose wire fingerprint has
// drifted (uTLS update, hpack/framer change) fails the build instead of
// silently impersonating nothing.
//
// Usage:
//
//	go build -o gocurl . && go run ./selftest              # verify all
//	go run ./selftest chrome-133                           # one profile
//
// The fingerprint endpoint defaults to https://tls.peet.ws/api/all and can
// be overridden with SELFTEST_ENDPOINT; the binary under test with
// SELFTEST_BINARY (default ./gocurl).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ameshkov/gocurl/internal/ja4h"
	"github.com/ameshkov/gocurl/internal/profile"
)

// echoResponse is the subset of tls.peet.ws/api/all we verify against.
type echoResponse struct {
	Method string `json:"method"`
	TLS    struct {
		JA3Hash string `json:"ja3_hash"`
		JA4     string `json:"ja4"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprintHash string      `json:"akamai_fingerprint_hash"`
		SentFrames            []sentFrame `json:"sent_frames"`
	} `json:"http2"`
}

// sentFrame is one frame the server saw on the client connection.
type sentFrame struct {
	FrameType string   `json:"frame_type"`
	Headers   []string `json:"headers"`
}

func main() {
	endpoint := os.Getenv("SELFTEST_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://tls.peet.ws/api/all"
	}

	bin := os.Getenv("SELFTEST_BINARY")
	if bin == "" {
		bin = "./gocurl"
	}

	names := profile.Names()
	if len(os.Args) > 1 {
		names = os.Args[1:]
	}

	failed := false
	for _, name := range names {
		prof, err := profile.Get(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", name, err)
			failed = true
			continue
		}
		if len(prof.Fingerprints) == 0 {
			fmt.Printf("skip %s (no declared fingerprints)\n", name)
			continue
		}
		if err := verifyProfile(bin, prof, endpoint); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", name, err)
			failed = true
			continue
		}
		fmt.Printf("ok   %s\n", name)
	}

	if failed {
		os.Exit(1)
	}
}

// verifyProfile sends one request through the compiled binary with the
// profile active and diffs the echo endpoint's fingerprints against the
// profile's declared hashes.
func verifyProfile(bin string, prof *profile.Profile, endpoint string) error {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "--impersonate", prof.Name, endpoint)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := runWithTimeout(cmd, 60*time.Second); err != nil {
		return fmt.Errorf("binary failed: %v, stderr: %s", err, truncate(stderr.String(), 512))
	}

	var echo echoResponse
	if err := json.Unmarshal(stdout.Bytes(), &echo); err != nil {
		return fmt.Errorf("parsing echo response: %w, body: %s", err, truncate(stdout.String(), 512))
	}

	actual := map[string]string{
		"ja3_hash":                echo.TLS.JA3Hash,
		"ja4":                     echo.TLS.JA4,
		"akamai_fingerprint_hash": echo.HTTP2.AkamaiFingerprintHash,
	}
	// JA4H is not exposed by the echo endpoint; compute it from the request
	// HEADERS frame the server recorded.
	for _, f := range echo.HTTP2.SentFrames {
		if f.FrameType == "HEADERS" {
			method := echo.Method
			if method == "" {
				method = "GET"
			}
			actual["ja4h"] = ja4h.Fingerprint(method, f.Headers)
			break
		}
	}

	var mismatches []string
	for key, declared := range prof.Fingerprints {
		got, ok := actual[key]
		if !ok {
			// Non-hash metadata keys (e.g. ja3_note) are annotations, not
			// assertions — skip them.
			continue
		}
		matched := false
		for _, acceptable := range declared.Any {
			if got == acceptable {
				matched = true
				break
			}
		}
		if !matched {
			mismatches = append(mismatches, fmt.Sprintf("%s: declared %v, actual %s", key, declared.Any, got))
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("fingerprint drift: %s", strings.Join(mismatches, "; "))
	}

	return nil
}

// runWithTimeout runs cmd with a hard timeout, killing it on expiry.
func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	timer := time.AfterFunc(timeout, func() {
		_ = cmd.Process.Kill()
	})
	defer timer.Stop()

	return cmd.Run()
}

// truncate cuts s to n runes, appending an ellipsis.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n] + "…"
}

// referenced so the http import stays honest if the endpoint logic grows;
// the current flow shells out to the binary only.
var _ = http.MethodGet
var _ io.Reader
