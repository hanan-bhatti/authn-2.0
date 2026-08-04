// Copyright (c) 2026 Hanan Bhatti
// This file is part of Authn.
//
// Authn is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Authn is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Authn.  If not, see <https://www.gnu.org/licenses/>.

package session

import (
	"strings"
)

// DeviceInfo represents parsed user agent & location details.
type DeviceInfo struct {
	Browser string `json:"browser"`
	OS      string `json:"os"`
	Device  string `json:"device"`
	Label   string `json:"label"` // e.g. "Chrome 127 on macOS"
}

// ParseUserAgent extracts human-readable browser, OS, and device type from User-Agent string.
func ParseUserAgent(ua string) DeviceInfo {
	if ua == "" {
		return DeviceInfo{Browser: "Unknown", OS: "Unknown", Device: "Desktop", Label: "Unknown Device"}
	}

	browser := "Browser"
	os := "Unknown OS"
	device := "Desktop"

	// Simple OS detection
	switch {
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		os = "macOS"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Android"):
		os = "Android"
		device = "Mobile"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
		device = "Mobile"
		if strings.Contains(ua, "iPad") {
			device = "Tablet"
		}
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}

	// Simple Browser detection
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Edg/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/"):
		browser = "Safari"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	}

	label := browser + " on " + os
	return DeviceInfo{
		Browser: browser,
		OS:      os,
		Device:  device,
		Label:   label,
	}
}
