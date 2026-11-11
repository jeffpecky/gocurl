// capture prints the live fingerprint hashes observed for a profile, as a
// ready-to-paste "fingerprints" JSON block for the profile's file.  Run it
// whenever a profile is added or refreshed (Phase 4 maintenance loop), then
// paste the output into internal/profile/profiles/<name>.json and let the
// selftest gate enforce it from then on.
//
// Usage:
//
//	go build -o gocurl . && go run ./selftest -capture chrome-133
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	bin := flag.String("binary", "./gocurl", "path to the compiled gocurl binary")
	endpoint := flag.String("endpoint", "https://tls.peet.ws/api/all", "fingerprint echo endpoint")
	profileName := flag.String("capture", "", "profile name to capture")
	flag.Parse()

	if *profileName == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./selftest -capture <profile> [-binary <bin>] [-endpoint <url>]")
		os.Exit(2)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(*bin, "--impersonate", *profileName, *endpoint)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v, stderr: %s\n", err, stderr.String())
		os.Exit(1)
	}

	var resp struct {
		TLS struct {
			JA3Hash string `json:"ja3_hash"`
			JA4     string `json:"ja4"`
		} `json:"tls"`
		HTTP2 struct {
			AkamaiFingerprint     string `json:"akamai_fingerprint"`
			AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
		} `json:"http2"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		fmt.Fprintf(os.Stderr, "parsing echo response: %v, body: %.512s\n", err, stdout.String())
		os.Exit(1)
	}

	out := map[string]string{
		"ja4":                     resp.TLS.JA4,
		"akamai_fingerprint_hash": resp.HTTP2.AkamaiFingerprintHash,
	}
	// Chrome 106+ shuffles extensions per handshake, so ja3_hash is only
	// stable for browsers without the shuffler (Firefox, Safari, iOS).
	// Include it when it repeats across two runs; otherwise note it.
	if ja3 := stableJA3(*bin, *profileName, *endpoint); ja3 != "" {
		out["ja3_hash"] = ja3
	} else {
		out["ja3_note"] = "unstable: browser shuffles extensions per handshake (real browser behavior); pinned by ja4 + akamai hash"
	}

	b, _ := json.MarshalIndent(out, "", "    ")
	fmt.Println(string(b))
}

// stableJA3 runs the request twice and returns the ja3_hash only if both
// runs agree.
func stableJA3(bin, profileName, endpoint string) string {
	hashes := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		var stdout bytes.Buffer
		cmd := exec.Command(bin, "--impersonate", profileName, endpoint)
		cmd.Stdout = &stdout
		if err := cmd.Run(); err != nil {
			return ""
		}
		var resp struct {
			TLS struct {
				JA3Hash string `json:"ja3_hash"`
			} `json:"tls"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
			return ""
		}
		if resp.TLS.JA3Hash == "" {
			return ""
		}
		hashes = append(hashes, resp.TLS.JA3Hash)
	}
	if hashes[0] == hashes[1] {
		return hashes[0]
	}

	return ""
}
