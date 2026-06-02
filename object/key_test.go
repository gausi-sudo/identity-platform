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

	"github.com/xorm-io/core"
)

// TestGetMaskedKeyMasksAccessSecret is the regression test for TC-FFE57E86.
// GetMaskedKey must set AccessSecret to "***" and leave all other fields intact.
func TestGetMaskedKeyMasksAccessSecret(t *testing.T) {
	key := &Key{
		Owner:        "test-org",
		Name:         "test-key",
		AccessKey:    "AK-PUBLIC",
		AccessSecret: "super-secret-value",
		State:        "Active",
	}

	masked := GetMaskedKey(key)

	if masked.AccessSecret != "***" {
		t.Errorf("GetMaskedKey() AccessSecret = %q, want \"***\"", masked.AccessSecret)
	}
	if masked.AccessKey != key.AccessKey {
		t.Errorf("GetMaskedKey() should not touch AccessKey, got %q", masked.AccessKey)
	}
	if masked.State != key.State {
		t.Errorf("GetMaskedKey() should not touch State, got %q", masked.State)
	}
}

// TestGetMaskedKeyNil ensures GetMaskedKey handles a nil pointer without panicking.
func TestGetMaskedKeyNil(t *testing.T) {
	if got := GetMaskedKey(nil); got != nil {
		t.Errorf("GetMaskedKey(nil) = %v, want nil", got)
	}
}

// TestUpdateKeyPreservesCredentials is the regression test for TC-B393BF04.
// UpdateKey must not accept caller-supplied accessKey / accessSecret — those
// fields must remain at their original values regardless of what the caller POSTs.
// Requires a live SQLite database (run ./start.sh && ./seed-local-data.sh first).
func TestUpdateKeyPreservesCredentials(t *testing.T) {
	InitConfig()

	const owner = "built-in"
	const name = "regression-tc-b393bf04"
	const origAccessKey = "AK-ORIGINAL"
	const origAccessSecret = "SECRET-ORIGINAL"

	// Insert a fresh key directly so this test is self-contained.
	key := &Key{
		Owner:        owner,
		Name:         name,
		DisplayName:  "Regression test key",
		AccessKey:    origAccessKey,
		AccessSecret: origAccessSecret,
		State:        "Active",
	}
	_, err := ormer.Engine.Insert(key)
	if err != nil {
		t.Fatalf("setup: insert test key: %v", err)
	}
	t.Cleanup(func() {
		ormer.Engine.ID(core.PK{owner, name}).Delete(&Key{})
	})

	// Attempt to overwrite credentials via UpdateKey (simulates the attacker request).
	updated := *key
	updated.AccessKey = "AK-ATTACKER"
	updated.AccessSecret = "SECRET-ATTACKER"
	updated.DisplayName = "should be accepted"

	affected, err := UpdateKey(owner+"/"+name, &updated)
	if err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}
	if !affected {
		t.Fatal("UpdateKey reported no rows affected")
	}

	// Read back from DB and verify credentials are unchanged.
	stored, err := getKey(owner, name)
	if err != nil {
		t.Fatalf("getKey after update: %v", err)
	}
	if stored == nil {
		t.Fatal("key not found after update")
	}

	if stored.AccessKey != origAccessKey {
		t.Errorf("UpdateKey overwrote AccessKey: got %q, want %q (original)", stored.AccessKey, origAccessKey)
	}
	if stored.AccessSecret != origAccessSecret {
		t.Errorf("UpdateKey overwrote AccessSecret: got %q, want %q (original)", stored.AccessSecret, origAccessSecret)
	}
	// Non-credential field should have been updated.
	if stored.DisplayName != "should be accepted" {
		t.Errorf("UpdateKey should allow DisplayName update, got %q", stored.DisplayName)
	}
}
