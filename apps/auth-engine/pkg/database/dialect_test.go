/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/database/dialect_test.go
 * Tier: Shared Package / Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package database

import (
	"strings"
	"testing"

	"entgo.io/ent/dialect"
)

func TestResolveSelectsDialectFromScheme(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		wantDialect string
		wantDriver  string
	}{
		{"postgres", "postgres://u:p@localhost:5432/authn", dialect.Postgres, "postgres"},
		{"postgresql alias", "postgresql://u:p@localhost:5432/authn", dialect.Postgres, "postgres"},
		{"mysql", "mysql://u:p@localhost:3306/authn", dialect.MySQL, "mysql"},
		{"sqlite", "sqlite://file:authn.db", dialect.SQLite, "sqlite3"},
		{"sqlite3 alias", "sqlite3://file:authn.db", dialect.SQLite, "sqlite3"},
		{"bare file", "file:authn.db?cache=shared", dialect.SQLite, "sqlite3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			driver, _, err := Resolve(tc.url)
			if err != nil {
				t.Fatalf("Resolve(%q) returned error: %v", tc.url, err)
			}
			if driver.Dialect != tc.wantDialect {
				t.Errorf("dialect = %q, want %q", driver.Dialect, tc.wantDialect)
			}
			if driver.SQLDriver != tc.wantDriver {
				t.Errorf("sql driver = %q, want %q", driver.SQLDriver, tc.wantDriver)
			}
		})
	}
}

// An unsupported engine must fail at startup with a message naming what is
// supported, rather than connecting and failing later on SQL syntax.
func TestResolveRejectsUnsupportedEngines(t *testing.T) {
	for _, url := range []string{
		"oracle://u:p@localhost:1521/authn",
		"sqlserver://u:p@localhost:1433/authn",
		"mongodb://localhost:27017/authn",
	} {
		_, _, err := Resolve(url)
		if err == nil {
			t.Errorf("Resolve(%q) should have failed: no ent dialect exists for it", url)
			continue
		}
		if !strings.Contains(err.Error(), "unsupported database scheme") {
			t.Errorf("error for %q should say the scheme is unsupported, got: %v", url, err)
		}
	}
}

func TestResolveRejectsMalformedURLs(t *testing.T) {
	for _, url := range []string{"", "   ", "authn.db", "localhost:5432/authn"} {
		if _, _, err := Resolve(url); err == nil {
			t.Errorf("Resolve(%q) should have failed", url)
		}
	}
}

// The password must never reach an error string, because startup errors are
// logged and frequently pasted into issue trackers.
func TestResolveErrorRedactsCredentials(t *testing.T) {
	_, _, err := Resolve("oracle://admin:sup3rs3cret@db.internal:1521/authn")
	if err == nil {
		t.Fatal("expected an error for an unsupported scheme")
	}
	if strings.Contains(err.Error(), "sup3rs3cret") {
		t.Errorf("error leaked the database password: %v", err)
	}

	_, _, err = Resolve("admin:sup3rs3cret@db.internal:1521/authn")
	if err == nil {
		t.Fatal("expected an error for a scheme-less URL")
	}
	if strings.Contains(err.Error(), "sup3rs3cret") {
		t.Errorf("error leaked the database password: %v", err)
	}
}

func TestMySQLDSNConversion(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "host and port become a tcp address",
			url:  "mysql://user:pass@db.internal:3306/authn",
			want: "user:pass@tcp(db.internal:3306)/authn?parseTime=true",
		},
		{
			name: "existing query is preserved",
			url:  "mysql://user:pass@db.internal:3306/authn?charset=utf8mb4",
			want: "user:pass@tcp(db.internal:3306)/authn?charset=utf8mb4&parseTime=true",
		},
		{
			name: "explicit parseTime is not duplicated",
			url:  "mysql://user:pass@db:3306/authn?parseTime=false",
			want: "user:pass@tcp(db:3306)/authn?parseTime=false",
		},
		{
			name: "a password containing @ still splits on the last one",
			url:  "mysql://user:p@ss@db:3306/authn",
			want: "user:p@ss@tcp(db:3306)/authn?parseTime=true",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, dsn, err := Resolve(tc.url)
			if err != nil {
				t.Fatalf("Resolve returned error: %v", err)
			}
			if dsn != tc.want {
				t.Errorf("dsn = %q, want %q", dsn, tc.want)
			}
		})
	}
}

// SQLite ignores foreign keys unless the connection asks for them, so the
// schema's cascade deletes would silently do nothing without _fk=1.
func TestSQLiteDSNEnablesForeignKeys(t *testing.T) {
	cases := []struct{ name, url string }{
		{"no query", "sqlite://file:authn.db"},
		{"existing query", "sqlite://file:authn.db?cache=shared"},
		{"sqlite3 scheme", "sqlite3://file:authn.db"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, dsn, err := Resolve(tc.url)
			if err != nil {
				t.Fatalf("Resolve returned error: %v", err)
			}
			if !strings.Contains(dsn, "_fk=1") {
				t.Errorf("dsn %q must enable foreign keys", dsn)
			}
			if strings.Contains(dsn, "sqlite://") {
				t.Errorf("dsn %q still carries the URL scheme", dsn)
			}
		})
	}

	// An explicit choice is respected rather than overridden.
	_, dsn, err := Resolve("sqlite://file:authn.db?_fk=0")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if strings.Contains(dsn, "_fk=1") {
		t.Errorf("an explicit _fk=0 must not be rewritten, got %q", dsn)
	}
}

func TestSupportedSchemesIsStable(t *testing.T) {
	first := strings.Join(SupportedSchemes(), ",")
	for i := 0; i < 5; i++ {
		if got := strings.Join(SupportedSchemes(), ","); got != first {
			t.Fatalf("SupportedSchemes must be deterministic: %q then %q", first, got)
		}
	}
	for _, want := range []string{"postgres", "mysql", "sqlite"} {
		if !strings.Contains(first, want) {
			t.Errorf("supported schemes %q should include %q", first, want)
		}
	}
}
