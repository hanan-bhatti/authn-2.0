/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/generate.go
 * Tier: Ent ORM Code Generator Trigger
 *
 * Description: Holds the go:generate directive that regenerates the ent client.
 *              Lives in the ent package rather than the module root: as
 *              `package main` at the root it had no main function, so
 *              `go build ./...` failed on the root package before compiling
 *              anything else.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package ent

//go:generate go run entgo.io/ent/cmd/ent generate --feature privacy,interceptor ./schema
