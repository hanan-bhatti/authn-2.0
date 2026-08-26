/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/session/parser.go
 * Tier: Session Management Layer / User-Agent Parsing
 *
 * Description: Best-effort user-agent parsing that turns the raw header recorded on a
 *              session into the browser, operating system and form factor shown in the
 *              session list, so a user can recognise their own devices.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package session

import (
	"strings"
)

// DeviceInfo is the human-readable description of the client behind a session.
type DeviceInfo struct {
	// Browser is the detected browser family, or "Browser" when unrecognised.
	Browser string `json:"browser"`
	// OS is the detected operating system, or "Unknown OS" when unrecognised.
	OS string `json:"os"`
	// Device is the form factor: "Desktop", "Mobile" or "Tablet".
	Device string `json:"device"`
	// Label is the display string combining browser and OS, e.g. "Chrome on macOS".
	Label string `json:"label"`
}

// ParseUserAgent derives browser, operating system and form factor from a
// User-Agent header, defaulting to a fully unknown device for an empty string.
//
// It is presentational only: user agents are client-supplied and trivially
// spoofed, so nothing may branch on the result for a security decision.
func ParseUserAgent(ua string) DeviceInfo {
	if ua == "" {
		return DeviceInfo{Browser: "Unknown", OS: "Unknown", Device: "Desktop", Label: "Unknown Device"}
	}

	browser := "Browser"
	os := "Unknown OS"
	device := "Desktop"

	// Order matters here too, and for a subtler reason than the browser switch
	// below. Every iOS user agent carries "like Mac OS X", and Android's carries
	// "Linux", so the specific platforms have to be tested before the desktop ones
	// they impersonate. An iPad running desktop-class Safari is indistinguishable
	// from a Mac by user agent alone and is reported as one.
	switch {
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
		device = "Mobile"
		if strings.Contains(ua, "iPad") {
			device = "Tablet"
		}
	case strings.Contains(ua, "Android"):
		os = "Android"
		// Android phones announce "Mobile"; tablets omit it. Without the token a
		// 13-inch tablet would be described to its owner as a phone.
		device = "Tablet"
		if strings.Contains(ua, "Mobile") {
			device = "Mobile"
		}
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "CrOS"):
		os = "ChromeOS"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}

	// Order matters: Edge and Chrome both advertise "Chrome/", and Safari's token
	// appears in Chrome's user agent too, so the more specific match comes first.
	// On iOS every browser is WebKit and none may ship its own engine, so they
	// identify themselves with a suffixed token — CriOS, FxiOS, EdgiOS — while
	// still carrying "Safari/". Those are what the owner recognises as the browser
	// they chose, so they are read before the Safari fallback.
	switch {
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "EdgiOS/"):
		browser = "Edge"
	case strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"):
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
