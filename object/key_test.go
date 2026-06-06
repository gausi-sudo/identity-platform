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

// TestUpdateKeyPreservesImmutableFields covers TC-A3CD4FD7: UpdateKey must not
// allow a caller to overwrite identity-binding or credential fields
// (Type, User, Application, AccessKey, AccessSecret) regardless of what the
// request body contains.  Mutable fields (DisplayName, State, ExpireTime) must
// still be writable.
//
// Run against unfixed code — each immutable-field assertion should FAIL because
// AllCols().Update overwrites every column.  Run again after the fix — all
// assertions should PASS.
func TestUpdateKeyPreservesImmutableFields(t *testing.T) {
	createDatabase = false
	InitConfig()

	original := &Key{
		Owner:        "built-in",
		Name:         "test-regression-key",
		DisplayName:  "Original Display Name",
		Type:         "User",
		Organization: "built-in",
		User:         "alice",
		AccessKey:    "AK-ORIGINAL",
		AccessSecret: "SECRET-ORIGINAL",
		State:        "Active",
	}

	// Insert; clean up regardless of test outcome.
	_, err := ormer.Engine.Insert(original)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() {
		ormer.Engine.Delete(&Key{Owner: original.Owner, Name: original.Name})
	})

	// Attempt to overwrite every field via a tampered update body.
	tampered := &Key{
		Owner:        original.Owner,
		Name:         original.Name,
		DisplayName:  "Updated Display Name", // mutable — should change
		Type:         "Organization",          // immutable — must not change
		Organization: "evil-org",              // immutable — must not change
		User:         "bob",                   // immutable — must not change
		AccessKey:    "AK-PWNED",              // immutable — must not change
		AccessSecret: "SECRET-PWNED",          // immutable — must not change
		State:        "Inactive",              // mutable — should change
	}

	updated, err := UpdateKey(original.Owner+"/"+original.Name, tampered)
	if err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}
	if !updated {
		t.Fatal("UpdateKey reported no rows affected")
	}

	got, err := getKey(original.Owner, original.Name)
	if err != nil {
		t.Fatalf("getKey: %v", err)
	}

	// --- immutable fields must be unchanged ---
	if got.Type != original.Type {
		t.Errorf("Type: got %q, want %q (immutable field was overwritten)", got.Type, original.Type)
	}
	if got.Organization != original.Organization {
		t.Errorf("Organization: got %q, want %q (immutable field was overwritten)", got.Organization, original.Organization)
	}
	if got.User != original.User {
		t.Errorf("User: got %q, want %q (immutable field was overwritten)", got.User, original.User)
	}
	if got.AccessKey != original.AccessKey {
		t.Errorf("AccessKey: got %q, want %q (immutable field was overwritten)", got.AccessKey, original.AccessKey)
	}
	if got.AccessSecret != original.AccessSecret {
		t.Errorf("AccessSecret: got %q, want %q (immutable field was overwritten)", got.AccessSecret, original.AccessSecret)
	}

	// --- mutable fields must reflect the update ---
	if got.DisplayName != tampered.DisplayName {
		t.Errorf("DisplayName: got %q, want %q (mutable field was not updated)", got.DisplayName, tampered.DisplayName)
	}
	if got.State != tampered.State {
		t.Errorf("State: got %q, want %q (mutable field was not updated)", got.State, tampered.State)
	}
}
