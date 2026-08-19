/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/useradmin/repository_test.go
 * Tier: Unit Tests / Admin User Directory
 *
 * Covers the parts of the directory listing and the profile patch that decide an
 * outcome without touching a database: page bounds, the sort allowlist, and the
 * metadata merge.
 *
 * The page bounds and the allowlist are the two places a query parameter reaches
 * something costly — an unbounded scan and a generated ORDER BY identifier — so
 * each is asserted at its boundary rather than at a representative value.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package useradmin

import (
	"reflect"
	"testing"
)

// TestListFilterPage checks the clamp on both sides and the negative-offset
// floor. A caller asking for more than the maximum must be served the maximum
// rather than refused, because the handler echoes what it got and a console pages
// on that number.
func TestListFilterPage(t *testing.T) {
	cases := []struct {
		name       string
		filter     ListFilter
		wantLimit  int
		wantOffset int
	}{
		{
			name:      "zero value takes the default page",
			filter:    ListFilter{},
			wantLimit: defaultPageSize,
		},
		{
			name:      "negative limit takes the default rather than inverting",
			filter:    ListFilter{Limit: -10},
			wantLimit: defaultPageSize,
		},
		{
			name:      "limit at the maximum is honoured",
			filter:    ListFilter{Limit: maxPageSize},
			wantLimit: maxPageSize,
		},
		{
			name:      "limit past the maximum is clamped, not refused",
			filter:    ListFilter{Limit: maxPageSize + 1},
			wantLimit: maxPageSize,
		},
		{
			name:       "negative offset floors at zero",
			filter:     ListFilter{Limit: 10, Offset: -5},
			wantLimit:  10,
			wantOffset: 0,
		},
		{
			name:       "offset is passed through",
			filter:     ListFilter{Limit: 10, Offset: 40},
			wantLimit:  10,
			wantOffset: 40,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limit, offset := tc.filter.page()
			if limit != tc.wantLimit {
				t.Errorf("limit = %d, want %d", limit, tc.wantLimit)
			}
			if offset != tc.wantOffset {
				t.Errorf("offset = %d, want %d", offset, tc.wantOffset)
			}
		})
	}
}

// TestIsSortable checks the allowlist admits every documented key and nothing
// else. The rejected cases are the shapes a caller reaches this with: a column
// that exists on the row but is not offered, and an injection attempt.
func TestIsSortable(t *testing.T) {
	for _, key := range []string{"created_at", "updated_at", "last_sign_in_at", "email", "status"} {
		if !IsSortable(key) {
			t.Errorf("IsSortable(%q) = false, want true", key)
		}
	}

	for _, key := range []string{"", "password_hash", "id", "CREATED_AT", "created_at desc", "created_at; drop table users"} {
		if IsSortable(key) {
			t.Errorf("IsSortable(%q) = true, want false", key)
		}
	}
}

// TestSortableFieldsIsStable checks the reported keys are sorted, so an error
// message and the API documentation do not reorder between runs over a map.
func TestSortableFieldsIsStable(t *testing.T) {
	want := []string{"created_at", "email", "last_sign_in_at", "status", "updated_at"}
	if got := SortableFields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SortableFields() = %v, want %v", got, want)
	}
}

// TestMergeMetadata checks a patch adds and overwrites its own keys, leaves the
// rest of the stored map alone, and removes a key set to null.
//
// Leaving untouched keys alone is the property that matters: the column carries
// flags written by other flows, so a replacing write would let a profile edit
// clear state it never mentioned.
func TestMergeMetadata(t *testing.T) {
	cases := []struct {
		name    string
		current map[string]interface{}
		patch   map[string]interface{}
		want    map[string]interface{}
	}{
		{
			name:    "adds a new key without disturbing the others",
			current: map[string]interface{}{"recovery_email_verified": true},
			patch:   map[string]interface{}{"plan": "pro"},
			want:    map[string]interface{}{"recovery_email_verified": true, "plan": "pro"},
		},
		{
			name:    "overwrites only the key it names",
			current: map[string]interface{}{"plan": "free", "recovery_email_verified": true},
			patch:   map[string]interface{}{"plan": "pro"},
			want:    map[string]interface{}{"plan": "pro", "recovery_email_verified": true},
		},
		{
			name:    "a null value removes the key",
			current: map[string]interface{}{"plan": "pro", "recovery_email_verified": true},
			patch:   map[string]interface{}{"plan": nil},
			want:    map[string]interface{}{"recovery_email_verified": true},
		},
		{
			name:    "removing an absent key is not an error",
			current: map[string]interface{}{"plan": "pro"},
			patch:   map[string]interface{}{"never_set": nil},
			want:    map[string]interface{}{"plan": "pro"},
		},
		{
			name:    "an empty patch preserves the stored map",
			current: map[string]interface{}{"plan": "pro"},
			patch:   map[string]interface{}{},
			want:    map[string]interface{}{"plan": "pro"},
		},
		{
			name:    "a patch against no stored metadata stands alone",
			current: nil,
			patch:   map[string]interface{}{"plan": "pro"},
			want:    map[string]interface{}{"plan": "pro"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeMetadata(tc.current, tc.patch)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mergeMetadata() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMergeMetadataDoesNotMutateStored checks the merge builds a new map. The
// caller passes the loaded row's own map, and writing through it would leave the
// in-memory row disagreeing with what a failed save left in the database.
func TestMergeMetadataDoesNotMutateStored(t *testing.T) {
	current := map[string]interface{}{"plan": "free", "keep": true}

	mergeMetadata(current, map[string]interface{}{"plan": "pro", "keep": nil})

	if current["plan"] != "free" {
		t.Errorf("stored plan = %v, want it left at free", current["plan"])
	}
	if _, present := current["keep"]; !present {
		t.Error("stored map lost a key the merge only removed from its own result")
	}
}

// TestProfilePatchIsEmpty checks the guard that refuses a request changing
// nothing. A pointer to the empty string is a request to clear a value, so it
// counts as a change; a nil pointer does not.
func TestProfilePatchIsEmpty(t *testing.T) {
	empty := ""
	value := "set"

	cases := []struct {
		name  string
		patch ProfilePatch
		want  bool
	}{
		{name: "no fields", patch: ProfilePatch{}, want: true},
		{name: "name set", patch: ProfilePatch{Name: &value}},
		{name: "username cleared", patch: ProfilePatch{Username: &empty}},
		{name: "avatar set", patch: ProfilePatch{AvatarURL: &value}},
		{name: "phone cleared", patch: ProfilePatch{PhoneNumber: &empty}},
		{name: "locale set", patch: ProfilePatch{Locale: &value}},
		{name: "metadata present but empty", patch: ProfilePatch{Metadata: map[string]interface{}{}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.patch.IsEmpty(); got != tc.want {
				t.Fatalf("IsEmpty() = %v, want %v", got, tc.want)
			}
		})
	}
}
