package ja4h

import "testing"

// TestFingerprintChrome pins the algorithm against a real Chrome 133 capture
// (https://tls.peet.ws/api/all, --impersonate chrome-133).
func TestFingerprintChrome(t *testing.T) {
	headers := []string{
		":method: GET",
		":authority: tls.peet.ws",
		":scheme: https",
		":path: /api/all",
		`sec-ch-ua: ""Chromium";v="133", "Not(A:Brand";v="24""`,
		"sec-ch-ua-mobile: ?0",
		`sec-ch-ua-platform: "Windows"`,
		"upgrade-insecure-requests: 1",
		"user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"sec-fetch-site: none",
		"sec-fetch-mode: navigate",
		"sec-fetch-user: ?1",
		"sec-fetch-dest: document",
		"accept-encoding: gzip, deflate, br, zstd",
		"accept-language: en-US,en;q=0.9",
		"priority: u=0, i",
	}

	const want = "ge20nn13enus_0c2c1d640f3e_000000000000_000000000000"
	if got := Fingerprint("GET", headers); got != want {
		t.Fatalf("Fingerprint = %s, want %s", got, want)
	}
}

// TestFingerprintCookies checks the cookie and referer axes.
func TestFingerprintCookies(t *testing.T) {
	headers := []string{
		":method: GET",
		"referer: https://example.com/",
		"cookie: a=1; b=2",
		"accept-language: en-GB,en;q=0.9",
	}

	got := Fingerprint("GET", headers)
	if got[:13] != "ge20cr01engb_" {
		t.Fatalf("prefix = %q, want ge20cr01engb_", got[:13])
	}
	if got[13:26] == "_00000000000" {
		t.Fatal("cookie fields hashed as absent")
	}
}

// TestFingerprintMethod covers the method truncation and lowercasing axis.
func TestFingerprintMethod(t *testing.T) {
	got := Fingerprint("DELETE", []string{"accept: */*"})
	if got[:4] != "de20" {
		t.Fatalf("prefix = %q, want de20", got[:4])
	}
}
