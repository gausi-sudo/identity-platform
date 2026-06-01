// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"testing"
)

// setupKeyTestOrmer initialises an in-memory SQLite ormer scoped to the test
// and restores the previous global when done.
func setupKeyTestOrmer(t *testing.T) {
	t.Helper()
	prev := ormer
	t.Cleanup(func() { ormer = prev })

	var err error
	ormer, err = NewAdapter("sqlite", "file::memory:?mode=memory&cache=shared", "")
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if err = ormer.Engine.Sync2(new(Key)); err != nil {
		t.Fatalf("Sync2: %v", err)
	}
}

// TestUpdateKeyDoesNotOverwriteCredentials is a regression test for
// TC-DA1B0703: UpdateKey must not allow callers to change accessKey or
// accessSecret, which are immutable after creation.
func TestUpdateKeyDoesNotOverwriteCredentials(t *testing.T) {
	setupKeyTestOrmer(t)

	original := &Key{
		Owner:        "testorg",
		Name:         "testkey",
		AccessKey:    "ORIGINAL-AK",
		AccessSecret: "ORIGINAL-SECRET",
		DisplayName:  "Original Name",
		State:        "Active",
		CreatedTime:  "2026-01-01T00:00:00Z",
	}
	if _, err := ormer.Engine.Insert(original); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Attacker submits an update body with hijacked credentials.
	update := &Key{
		Owner:        "testorg",
		Name:         "testkey",
		AccessKey:    "HIJACKED-AK",
		AccessSecret: "HIJACKED-SECRET",
		DisplayName:  "Updated Name",
		State:        "Active",
	}
	ok, err := UpdateKey("testorg/testkey", update)
	if err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}
	if !ok {
		t.Fatal("UpdateKey returned false")
	}

	got, err := GetKey("testorg/testkey")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got == nil {
		t.Fatal("key not found after update")
	}

	if got.AccessKey != "ORIGINAL-AK" {
		t.Errorf("accessKey was overwritten: got %q, want %q", got.AccessKey, "ORIGINAL-AK")
	}
	if got.AccessSecret != "ORIGINAL-SECRET" {
		t.Errorf("accessSecret was overwritten: got %q, want %q", got.AccessSecret, "ORIGINAL-SECRET")
	}
	// Legitimate mutable field must have been applied.
	if got.DisplayName != "Updated Name" {
		t.Errorf("displayName not updated: got %q, want %q", got.DisplayName, "Updated Name")
	}
}
