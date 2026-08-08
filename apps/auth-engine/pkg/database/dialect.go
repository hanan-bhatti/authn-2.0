/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/database/dialect.go
 * Tier: Shared Package / Database Driver Resolution
 *
 * Turns a database URL into the driver and dialect the ORM needs.
 *
 * The URL is the single source of truth. There is no separate "database type"
 * setting, because two settings that must agree eventually will not:
 *
 *   postgres://user:pass@localhost:5432/authn?sslmode=require
 *   mysql://user:pass@localhost:3306/authn?parseTime=true
 *   sqlite://file:authn.db?_fk=1
 *
 * Resolution is a table lookup keyed by URL scheme, following the same pattern
 * as Go's own database/sql driver registry. Adding support for another engine
 * means adding a row, not editing a branch, so no dispatch logic grows a new
 * arm each time.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package database

import (
	"fmt"
	"sort"
	"strings"

	"entgo.io/ent/dialect"

	// Database drivers register themselves with database/sql via their init
	// functions. They are imported for that side effect alone, which is why
	// each is blank-imported.
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// Driver describes how to connect to one database engine.
type Driver struct {
	// Dialect is the ent dialect constant used to generate SQL for this engine.
	Dialect string
	// SQLDriver is the name the engine's driver registered with database/sql.
	SQLDriver string
	// normalize converts the configured URL into the exact form the driver
	// expects, since not every driver accepts a standard URL.
	normalize func(rawURL string) string
}

// registry maps a URL scheme to the driver that serves it.
//
// Only engines that ent can generate a schema for appear here. ent supports
// PostgreSQL, MySQL and SQLite; there is no Oracle or SQL Server dialect, so
// those URLs are rejected at startup with a clear message rather than failing
// later with a confusing SQL syntax error.
var registry = map[string]Driver{
	"postgres": {
		Dialect:   dialect.Postgres,
		SQLDriver: "postgres",
		normalize: keepAsIs,
	},
	// Alias used by many hosted providers and ORMs.
	"postgresql": {
		Dialect:   dialect.Postgres,
		SQLDriver: "postgres",
		normalize: keepAsIs,
	},
	"mysql": {
		Dialect:   dialect.MySQL,
		SQLDriver: "mysql",
		normalize: mysqlDSN,
	},
	"sqlite": {
		Dialect:   dialect.SQLite,
		SQLDriver: "sqlite3",
		normalize: sqliteDSN,
	},
	"sqlite3": {
		Dialect:   dialect.SQLite,
		SQLDriver: "sqlite3",
		normalize: sqliteDSN,
	},
	// A bare file: URL is SQLite's own convention and appears in ent's docs.
	"file": {
		Dialect:   dialect.SQLite,
		SQLDriver: "sqlite3",
		normalize: keepAsIs,
	},
}

// Resolve inspects a database URL and returns the driver serving its scheme,
// together with the connection string that driver expects.
//
// Returns an error when the URL carries no recognisable scheme, or when the
// scheme belongs to an engine the ORM cannot generate a schema for. Both are
// startup failures: the process cannot usefully continue without a database.
func Resolve(databaseURL string) (Driver, string, error) {
	trimmed := strings.TrimSpace(databaseURL)
	if trimmed == "" {
		return Driver{}, "", fmt.Errorf("database URL is empty")
	}

	// The scheme is everything before the first colon. Splitting on ":" rather
	// than "://" is deliberate: SQLite's own form is "file:authn.db", with a
	// single colon and no authority component.
	scheme, _, found := strings.Cut(trimmed, ":")
	if !found || scheme == "" {
		return Driver{}, "", fmt.Errorf(
			"database URL %q has no scheme: expected a form such as %s",
			redact(trimmed), strings.Join(exampleURLs(), " or "))
	}

	driver, known := registry[strings.ToLower(scheme)]
	if !known {
		return Driver{}, "", fmt.Errorf(
			"unsupported database scheme %q in %q: this engine supports %s",
			scheme, redact(trimmed), strings.Join(SupportedSchemes(), ", "))
	}

	return driver, driver.normalize(trimmed), nil
}

// SupportedSchemes returns the URL schemes this build accepts, sorted so the
// list reads the same in every error message and log line.
func SupportedSchemes() []string {
	schemes := make([]string, 0, len(registry))
	for scheme := range registry {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)
	return schemes
}

// exampleURLs returns one illustrative URL per supported engine, used to make
// a "no scheme" error actionable.
func exampleURLs() []string {
	return []string{
		"postgres://user:pass@host:5432/authn",
		"mysql://user:pass@host:3306/authn",
		"sqlite://file:authn.db?_fk=1",
	}
}

// keepAsIs passes a URL through unchanged, for drivers that accept URL form.
func keepAsIs(rawURL string) string { return rawURL }

// mysqlDSN rewrites a mysql:// URL into the DSN go-sql-driver/mysql expects,
// which is not a URL:
//
//	mysql://user:pass@host:3306/authn?parseTime=true
//	  becomes
//	user:pass@tcp(host:3306)/authn?parseTime=true
//
// parseTime=true is appended when absent, because without it the driver hands
// back DATETIME columns as raw bytes and every timestamp scan fails.
func mysqlDSN(rawURL string) string {
	body := strings.TrimPrefix(rawURL, "mysql://")

	credentials, remainder := "", body
	if idx := strings.LastIndex(body, "@"); idx != -1 {
		credentials, remainder = body[:idx+1], body[idx+1:]
	}

	hostPort, pathAndQuery := remainder, ""
	if idx := strings.Index(remainder, "/"); idx != -1 {
		hostPort, pathAndQuery = remainder[:idx], remainder[idx:]
	}

	dsn := credentials + "tcp(" + hostPort + ")" + pathAndQuery

	if !strings.Contains(dsn, "parseTime=") {
		separator := "?"
		if strings.Contains(dsn, "?") {
			separator = "&"
		}
		dsn += separator + "parseTime=true"
	}
	return dsn
}

// sqliteDSN strips the sqlite:// prefix, leaving the file: form the driver
// expects, and enables foreign-key enforcement when the caller has not.
//
// SQLite ignores foreign keys unless asked, so without _fk=1 the cascade
// deletes and referential guarantees the schema relies on silently do nothing.
func sqliteDSN(rawURL string) string {
	dsn := strings.TrimPrefix(rawURL, "sqlite3://")
	dsn = strings.TrimPrefix(dsn, "sqlite://")

	if !strings.Contains(dsn, "_fk=") {
		separator := "?"
		if strings.Contains(dsn, "?") {
			separator = "&"
		}
		dsn += separator + "_fk=1"
	}
	return dsn
}

// DescribeURL returns a credential-free summary of a database URL, safe to
// write to logs. An unparseable value still has its credentials stripped.
func DescribeURL(databaseURL string) string {
	return redact(strings.TrimSpace(databaseURL))
}

// redact removes credentials from a URL so it can appear in an error message or
// log line without leaking the database password.
//
// It does not assume the URL is well formed: these messages exist precisely to
// describe malformed input, so a value with credentials but no scheme must be
// redacted too. Everything before the last "@" in the authority is replaced.
func redact(rawURL string) string {
	prefix, remainder := "", rawURL
	if scheme, rest, found := strings.Cut(rawURL, "://"); found {
		prefix, remainder = scheme+"://", rest
	}

	// Credentials, when present, sit before the last "@" of the authority and
	// therefore before the first "/" that begins the path.
	authority, path := remainder, ""
	if idx := strings.Index(remainder, "/"); idx != -1 {
		authority, path = remainder[:idx], remainder[idx:]
	}

	if idx := strings.LastIndex(authority, "@"); idx != -1 {
		return prefix + "***@" + authority[idx+1:] + path
	}
	return rawURL
}
