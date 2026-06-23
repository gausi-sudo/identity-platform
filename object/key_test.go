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

// TestUpdateKeyCannotOverwriteSecret verifies that UpdateKey does not persist
// accessSecret or accessKey when those fields are supplied in the update body.
// The UI renders both fields as read-only; the backend must enforce the same
// invariant so an org-admin cannot take over an API client's identity by
// directly calling the update-key endpoint.
func TestUpdateKeyCannotOverwriteSecret(t *testing.T) {
	// Spin up an isolated in-memory SQLite so this test is self-contained.
	engine, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("create in-memory engine: %v", err)
	}
	defer engine.Close()

	if err = engine.Sync2(new(Key)); err != nil {
		t.Fatalf("sync schema: %v", err)
	}

	// Save and restore the global ormer so other tests are unaffected.
	origOrmer := ormer
	ormer = &Ormer{Engine: engine}
	defer func() { ormer = origOrmer }()

	const owner = "built-in"
	const name = "regression-key-secret"
	const originalSecret = "original-secret-value"
	const originalAccessKey = "original-access-key"

	key := &Key{
		Owner:        owner,
		Name:         name,
		DisplayName:  "Regression test key",
		Type:         "Organization",
		Organization: owner,
		AccessKey:    originalAccessKey,
		AccessSecret: originalSecret,
		State:        "Active",
	}
	if _, err = engine.Insert(key); err != nil {
		t.Fatalf("insert test key: %v", err)
	}

	// Simulate the attack: call UpdateKey with a different secret.
	mutated := *key
	mutated.AccessSecret = "hacked-secret"
	mutated.AccessKey = "hacked-access-key"
	mutated.DisplayName = "Updated display name" // this field IS allowed to change

	affected, err := UpdateKey(key.GetId(), &mutated)
	if err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}
	if !affected {
		t.Fatal("UpdateKey reported no rows affected; expected display name update to succeed")
	}

	// Re-fetch and assert immutable fields were NOT changed.
	stored, err := getKey(owner, name)
	if err != nil {
		t.Fatalf("getKey after update: %v", err)
	}
	if stored == nil {
		t.Fatal("key not found after update")
	}

	if stored.AccessSecret != originalSecret {
		t.Errorf("accessSecret was mutated: got %q, want %q (VULNERABILITY: org-admin can overwrite secrets)", stored.AccessSecret, originalSecret)
	}
	if stored.AccessKey != originalAccessKey {
		t.Errorf("accessKey was mutated: got %q, want %q", stored.AccessKey, originalAccessKey)
	}
	if stored.DisplayName != "Updated display name" {
		t.Errorf("displayName was not updated: got %q", stored.DisplayName)
	}
}
