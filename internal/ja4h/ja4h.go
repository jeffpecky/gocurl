// Package ja4h computes the FoxIO JA4H HTTP client fingerprint from a
// request's header list.  It is shared by the selftest (which verifies live
// traffic) and the capture tool (which emits profile declarations).
package ja4h

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Version is the JA4H HTTP/2 version token for a plain (https) request.
const Version = 20

// Fingerprint computes the JA4H value for a request.  Format:
//
//	{method[:2]}{20}{c|n}{r|n}{count:02d}{lang}_{headers_hash}_{cookie_name_hash}_{cookie_value_hash}
//
// Headers are "name: value" strings as they appear on the wire.  Pseudo-
// headers (":method: GET", ...) are ignored.  count excludes Cookie and
// Referer; absent cookies hash as zeros.
func Fingerprint(method string, headers []string) string {
	method = strings.ToLower(method)
	if len(method) > 2 {
		method = method[:2]
	}

	var names, cookieNames, cookieValues []string
	lang := ""
	hasReferer := false
	for _, h := range headers {
		if strings.HasPrefix(h, ":") {
			// Pseudo-header (":method: GET"): the name itself starts with ':'.
			continue
		}
		key, value, _ := strings.Cut(h, ":")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "cookie":
			for _, pair := range strings.Split(value, ";") {
				k, v, _ := strings.Cut(strings.TrimSpace(pair), "=")
				cookieNames = append(cookieNames, k)
				cookieValues = append(cookieValues, v)
			}
		case "referer":
			hasReferer = true
		}
		if key != "cookie" && key != "referer" {
			names = append(names, key)
			if key == "accept-language" {
				lang = value
			}
		}
	}

	lang = strings.ToLower(lang)
	lang = strings.ReplaceAll(lang, ";", ",")
	lang = strings.ReplaceAll(lang, "-", "")
	lang = strings.TrimSpace(strings.Split(lang, ",")[0])
	if len(lang) > 4 {
		lang = lang[:4]
	}
	lang += "0000"
	lang = lang[:4]

	count := len(names)
	if count > 99 {
		count = 99
	}

	c := "n"
	if len(cookieNames) > 0 {
		c = "c"
	}
	r := "n"
	if hasReferer {
		r = "r"
	}

	return fmt.Sprintf("%s%d%s%s%02d%s_%s_%s_%s",
		method, Version, c, r, count, lang,
		ShortHash(names), ShortHash(cookieNames), ShortHash(cookieValues))
}

// ShortHash is the first 12 hex chars of sha256 over the comma-joined list,
// or twelve zeros for an empty list.
func ShortHash(list []string) string {
	if len(list) == 0 {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(strings.Join(list, ",")))

	return hex.EncodeToString(sum[:])[:12]
}
