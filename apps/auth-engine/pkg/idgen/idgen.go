/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/idgen/idgen.go
 * Tier: Core Package / Identifier Generator
 *
 * Description: Centralized identifier generation using full UUIDv4 with hyphens stripped (32 hex characters).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package idgen

import (
	"strings"

	"github.com/google/uuid"
)

// New returns a prefixed identifier using a full UUIDv4 with hyphens removed.
// For example:
//
//	idgen.New("tnt") -> "tnt_728fa19d48e24c1a9f3b1234567890ab"
//	idgen.New("")    -> "728fa19d48e24c1a9f3b1234567890ab"
//
// This function is the single source of truth for entity ID generation across
// the engine. Any change to the ID format in the future must be done here.
func New(prefix string) string {
	id := strings.ReplaceAll(uuid.New().String(), "-", "")
	if prefix == "" {
		return id
	}
	return prefix + "_" + id
}
