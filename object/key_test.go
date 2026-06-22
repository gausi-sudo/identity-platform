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

	"github.com/xorm-io/xorm"
	_ "modernc.org/sqlite"
)

// newKeyTestOrmer creates an isolated in-memory SQLite ormer for key tests and
// returns a cleanup func that restores the previous global ormer.
func newKeyTestOrmer(t *testing.T) func() {
	t.Helper()
	engine, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}
	if err := engine.Sync2(new(Key)); err != nil {
		t.Fatalf("failed to sync Key table: %v", err)
	}
	prev := ormer
	ormer = &Ormer{Engine: engine}
	return func() {
		engine.Close()
		ormer = prev
	}
}

// TestUpdateKeyCredentialsImmutable verifies that UpdateKey cannot overwrite
// accessKey or accessSecret even when attacker-supplied values are present in
// the update body.  This is a regression test for TC-7CEE0988.
func TestUpdateKeyCredentialsImmutable(t *testing.T) {
	cleanup := newKeyTestOrmer(t)
	defer cleanup()

	seed := &Key{
		Owner:        "built-in",
		Name:         "prod-signing-key",
		AccessKey:    "AK-ORIGINAL",
		AccessSecret: "SK-ORIGINAL",
		State:        "Active",
	}
	if _, err := ormer.Engine.Insert(seed); err != nil {
		t.Fatalf("insert seed key: %v", err)
	}

	// Attacker body matches the ?id= target org/name but injects new credentials.
	attacker := &Key{
		Owner:        "built-in",
		Name:         "prod-signing-key",
		DisplayName:  "legit-looking update",
		AccessKey:    "AK-PWNED",
		AccessSecret: "SK-PWNED",
		State:        "Inactive",
	}
	ok, err := UpdateKey("built-in/prod-signing-key", attacker)
	if err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}
	if !ok {
		t.Fatal("UpdateKey reported no affected rows")
	}

	got, err := GetKey("built-in/prod-signing-key")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got == nil {
		t.Fatal("key disappeared after update")
	}

	if got.AccessKey != "AK-ORIGINAL" {
		t.Errorf("accessKey overwritten: got %q, want %q", got.AccessKey, "AK-ORIGINAL")
	}
	if got.AccessSecret != "SK-ORIGINAL" {
		t.Errorf("accessSecret overwritten: got %q, want %q", got.AccessSecret, "SK-ORIGINAL")
	}
	// Safe mutable field — must have changed.
	if got.State != "Inactive" {
		t.Errorf("state not updated: got %q, want %q", got.State, "Inactive")
	}
}

// TestUpdateKeyPKImmutable verifies that UpdateKey cannot rename a key to a
// different owner/name by injecting those fields in the body.  With AllCols()
// the PK overwrite silently deletes the victim key and creates an
// attacker-controlled replacement.  This is a regression test for TC-7CEE0988.
func TestUpdateKeyPKImmutable(t *testing.T) {
	cleanup := newKeyTestOrmer(t)
	defer cleanup()

	seed := &Key{
		Owner: "built-in",
		Name:  "prod-signing-key",
		State: "Active",
	}
	if _, err := ormer.Engine.Insert(seed); err != nil {
		t.Fatalf("insert seed key: %v", err)
	}

	// Attacker body supplies a different owner/name than the ?id= target.
	attacker := &Key{
		Owner:        "test-org",
		Name:         "evil-key",
		DisplayName:  "HIJACKED",
		AccessKey:    "AK-EVIL",
		AccessSecret: "SK-EVIL",
	}
	_, err := UpdateKey("built-in/prod-signing-key", attacker)
	if err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	// Original key must still exist.
	original, err := GetKey("built-in/prod-signing-key")
	if err != nil {
		t.Fatalf("GetKey original: %v", err)
	}
	if original == nil {
		t.Error("original key was deleted — owner/name PK must not be overwritten by the update body")
	}

	// No attacker-controlled key should have been created.
	evil, err := GetKey("test-org/evil-key")
	if err != nil {
		t.Fatalf("GetKey evil: %v", err)
	}
	if evil != nil {
		t.Error("attacker-controlled key was created in test-org via PK overwrite")
	}
}
