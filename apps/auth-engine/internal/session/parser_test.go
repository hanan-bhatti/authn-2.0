/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/session/parser_test.go
 * Tier: Session Management Layer / User-Agent Parsing / Tests
 *
 * Description: Covers the user-agent parsing behind the device labels in the
 *              session list, with real headers taken from the platforms that
 *              impersonate each other: iOS advertises "like Mac OS X", Android
 *              advertises "Linux", Edge and Chrome both advertise "Chrome/",
 *              and Chrome advertises "Safari/". The ordering of the two
 *              switches is the whole subject.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package session

import "testing"

func TestParseUserAgent(t *testing.T) {
	cases := []struct {
		name    string
		ua      string
		browser string
		os      string
		device  string
	}{
		{
			name:    "iphone safari is not a mac",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
			browser: "Safari",
			os:      "iOS",
			device:  "Mobile",
		},
		{
			name:    "ipad safari is a tablet",
			ua:      "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
			browser: "Safari",
			os:      "iOS",
			device:  "Tablet",
		},
		{
			name:    "chrome on ios identifies itself as CriOS, not Safari",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
			browser: "Chrome",
			os:      "iOS",
			device:  "Mobile",
		},
		{
			name:    "firefox on ios identifies itself as FxiOS",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/133.0 Mobile/15E148 Safari/605.1.15",
			browser: "Firefox",
			os:      "iOS",
			device:  "Mobile",
		},
		{
			name:    "android phone announces Mobile",
			ua:      "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
			browser: "Chrome",
			os:      "Android",
			device:  "Mobile",
		},
		{
			name:    "android tablet omits Mobile",
			ua:      "Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			browser: "Chrome",
			os:      "Android",
			device:  "Tablet",
		},
		{
			name:    "firefox on android tablet says Tablet outright",
			ua:      "Mozilla/5.0 (Android 14; Tablet; rv:133.0) Gecko/133.0 Firefox/133.0",
			browser: "Firefox",
			os:      "Android",
			device:  "Tablet",
		},
		{
			name:    "macos safari",
			ua:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
			browser: "Safari",
			os:      "macOS",
			device:  "Desktop",
		},
		{
			name:    "windows edge is not chrome",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86",
			browser: "Edge",
			os:      "Windows",
			device:  "Desktop",
		},
		{
			name:    "chromeos is not linux",
			ua:      "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			browser: "Chrome",
			os:      "ChromeOS",
			device:  "Desktop",
		},
		{
			name:    "linux firefox",
			ua:      "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
			browser: "Firefox",
			os:      "Linux",
			device:  "Desktop",
		},
		{
			name:    "an unrecorded user agent is unknown rather than guessed",
			ua:      "",
			browser: "Unknown",
			os:      "Unknown",
			device:  "Desktop",
		},
		{
			name:    "a user agent from no known family degrades instead of failing",
			ua:      "curl/8.5.0",
			browser: "Browser",
			os:      "Unknown OS",
			device:  "Desktop",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUserAgent(tc.ua)
			if got.Browser != tc.browser {
				t.Errorf("browser = %q, want %q", got.Browser, tc.browser)
			}
			if got.OS != tc.os {
				t.Errorf("os = %q, want %q", got.OS, tc.os)
			}
			if got.Device != tc.device {
				t.Errorf("device = %q, want %q", got.Device, tc.device)
			}
			want := tc.browser + " on " + tc.os
			if tc.ua == "" {
				want = "Unknown Device"
			}
			if got.Label != want {
				t.Errorf("label = %q, want %q", got.Label, want)
			}
		})
	}
}
