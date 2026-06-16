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

// TestUpdateKeyDoesNotOverwriteImmutableFields is a regression test for TC-86005F44.
// UpdateKey must not allow callers to overwrite accessKey, accessSecret, or createdTime
// via the request body — these fields are credentials, not metadata.
// This test FAILS on unfixed code (AllCols writes every column) and
// PASSES after the fix (Cols whitelist excludes immutable fields).
func TestUpdateKeyDoesNotOverwriteImmutableFields(t *testing.T) {
	InitConfig()

	owner := "built-in"
	name := "regression-tc-86005f44"

	// Clean up any leftover state from a previous run.
	_, _ = ormer.Engine.Delete(&Key{Owner: owner, Name: name})

	original := &Key{
		Owner:        owner,
		Name:         name,
		DisplayName:  "Original Display",
		AccessKey:    "original-access-key",
		AccessSecret: "original-secret",
		State:        "Active",
		CreatedTime:  "2026-01-01T00:00:00Z",
	}
	if _, err := ormer.Engine.Insert(original); err != nil {
		t.Fatalf("insert test key: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.Delete(&Key{Owner: owner, Name: name})
	})

	// Send an update body with attacker-chosen values for immutable fields.
	update := &Key{
		Owner:        owner,
		Name:         name,
		DisplayName:  "Updated Display",
		AccessKey:    "attacker-key",
		AccessSecret: "attacker-secret",
		State:        "Inactive",
		CreatedTime:  "1970-01-01T00:00:00Z",
	}

	ok, err := UpdateKey(owner+"/"+name, update)
	if err != nil {
		t.Fatalf("UpdateKey error: %v", err)
	}
	if !ok {
		t.Fatal("UpdateKey returned false (key not found)")
	}

	got, err := getKey(owner, name)
	if err != nil {
		t.Fatalf("getKey after update: %v", err)
	}
	if got == nil {
		t.Fatal("key disappeared after update")
	}

	// Mutable fields should change.
	if got.DisplayName != "Updated Display" {
		t.Errorf("displayName: got %q, want %q", got.DisplayName, "Updated Display")
	}
	if got.State != "Inactive" {
		t.Errorf("state: got %q, want %q", got.State, "Inactive")
	}

	// Immutable fields must NOT change.
	if got.AccessKey != "original-access-key" {
		t.Errorf("TC-86005F44: accessKey was overwritten: got %q, want %q (mass-assignment bug)",
			got.AccessKey, "original-access-key")
	}
	if got.AccessSecret != "original-secret" {
		t.Errorf("TC-86005F44: accessSecret was overwritten: got %q, want %q (mass-assignment bug)",
			got.AccessSecret, "original-secret")
	}
	if got.CreatedTime != "2026-01-01T00:00:00Z" {
		t.Errorf("TC-86005F44: createdTime was overwritten: got %q, want %q",
			got.CreatedTime, "2026-01-01T00:00:00Z")
	}
}

// TestUpdateKeyDoesNotRetargetOrgOrUser is a regression test for TC-13666EEB.
// UpdateKey must not allow a caller to move a key into a different organization,
// application, or user — these binding fields are identity attributes set at
// creation and must be immutable via the update path.
// This test FAILS on unfixed code (organization/application/user in Cols whitelist)
// and PASSES after the fix (those fields removed from Cols).
func TestUpdateKeyDoesNotRetargetOrgOrUser(t *testing.T) {
	InitConfig()

	owner := "built-in"
	name := "regression-tc-13666eeb"

	_, _ = ormer.Engine.Delete(&Key{Owner: owner, Name: name})

	original := &Key{
		Owner:        owner,
		Name:         name,
		DisplayName:  "Original Display",
		Organization: "built-in",
		Application:  "app-built-in",
		User:         "alice",
		State:        "Active",
	}
	if _, err := ormer.Engine.Insert(original); err != nil {
		t.Fatalf("insert test key: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.Delete(&Key{Owner: owner, Name: name})
	})

	// Send an update body with attacker-chosen org/application/user targets.
	update := &Key{
		Owner:        owner,
		Name:         name,
		DisplayName:  "Updated Display",
		Organization: "attacker-org",
		Application:  "attacker-app",
		User:         "admin",
		State:        "Inactive",
	}

	ok, err := UpdateKey(owner+"/"+name, update)
	if err != nil {
		t.Fatalf("UpdateKey error: %v", err)
	}
	if !ok {
		t.Fatal("UpdateKey returned false (key not found)")
	}

	got, err := getKey(owner, name)
	if err != nil {
		t.Fatalf("getKey after update: %v", err)
	}
	if got == nil {
		t.Fatal("key disappeared after update")
	}

	// Mutable fields should change.
	if got.DisplayName != "Updated Display" {
		t.Errorf("displayName: got %q, want %q", got.DisplayName, "Updated Display")
	}

	// Binding fields must NOT change.
	if got.Organization != "built-in" {
		t.Errorf("TC-13666EEB: organization was retargeted: got %q, want %q (cross-org escalation bug)",
			got.Organization, "built-in")
	}
	if got.Application != "app-built-in" {
		t.Errorf("TC-13666EEB: application was retargeted: got %q, want %q",
			got.Application, "app-built-in")
	}
	if got.User != "alice" {
		t.Errorf("TC-13666EEB: user was retargeted: got %q, want %q",
			got.User, "alice")
	}
}
