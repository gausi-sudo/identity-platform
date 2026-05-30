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

//go:build !skipCi

package object

import (
	"testing"
)

// seedKey inserts a key directly and returns its id. Cleans up on t.Cleanup.
func seedKey(t *testing.T, k *Key) {
	t.Helper()
	_, err := ormer.Engine.InsertOne(k)
	if err != nil {
		t.Fatalf("seedKey: insert failed: %v", err)
	}
	t.Cleanup(func() {
		ormer.Engine.Delete(&Key{Owner: k.Owner, Name: k.Name})
	})
}

// TestUpdateKey_DoesNotOverwriteAccessSecret verifies that UpdateKey ignores
// any AccessSecret supplied in the request body (TC-B24B5FA6).
// Without the fix (AllCols), the attacker-supplied secret is written verbatim.
func TestUpdateKey_DoesNotOverwriteAccessSecret(t *testing.T) {
	InitConfig()

	original := &Key{
		Owner:        "built-in",
		Name:         "key-sec-test",
		DisplayName:  "Security Test Key",
		AccessKey:    "AK-SEC-TEST",
		AccessSecret: "original-secret-value",
		State:        "Active",
	}
	seedKey(t, original)

	updated := &Key{
		Owner:        "built-in",
		Name:         "key-sec-test",
		DisplayName:  "Updated Display",
		AccessKey:    "AK-SEC-TEST",
		AccessSecret: "attacker-chosen-secret",
		State:        "Active",
	}
	affected, err := UpdateKey("built-in/key-sec-test", updated)
	if err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}
	if !affected {
		t.Fatal("UpdateKey reported no row affected")
	}

	stored, err := GetKey("built-in/key-sec-test")
	if err != nil {
		t.Fatalf("GetKey error: %v", err)
	}
	if stored == nil {
		t.Fatal("key missing after update")
	}
	if stored.AccessSecret == "attacker-chosen-secret" {
		t.Errorf("SECURITY BUG (TC-B24B5FA6): UpdateKey accepted and stored an attacker-supplied accessSecret")
	}
	if stored.AccessSecret != original.AccessSecret {
		t.Errorf("accessSecret changed unexpectedly: got %q, want %q", stored.AccessSecret, original.AccessSecret)
	}
}

// TestUpdateKey_CannotMutatePrimaryKey verifies that supplying a different
// owner/name in the body does not move the row to another organization
// (TC-E54AB628 — cross-org BFLA via query/body mismatch + AllCols PK overwrite).
// Without the fix, the target row is destroyed and a new row appears under the
// attacker's org.
func TestUpdateKey_CannotMutatePrimaryKey(t *testing.T) {
	InitConfig()

	victim := &Key{
		Owner:        "built-in",
		Name:         "key-pk-test",
		DisplayName:  "Victim Key",
		AccessKey:    "AK-VICTIM",
		AccessSecret: "victim-secret",
		State:        "Active",
	}
	seedKey(t, victim)

	// Attacker body: different owner/name from the query id.
	attacker := &Key{
		Owner:        "test-org",
		Name:         "hijacked-key",
		DisplayName:  "Hijacked",
		AccessKey:    "AK-VICTIM",
		AccessSecret: "stolen-secret",
		State:        "Active",
	}
	// id targets the victim; body claims test-org ownership.
	_, err := UpdateKey("built-in/key-pk-test", attacker)
	if err != nil {
		// An error here is also acceptable — the request was rejected.
		t.Logf("UpdateKey returned error (acceptable): %v", err)
	}

	// Victim row must still exist.
	stored, err := GetKey("built-in/key-pk-test")
	if err != nil {
		t.Fatalf("GetKey error: %v", err)
	}
	if stored == nil {
		t.Errorf("SECURITY BUG (TC-E54AB628): victim key built-in/key-pk-test was destroyed by cross-org update body")
	}

	// Attacker's hijacked row must NOT have been created.
	hijacked, err := GetKey("test-org/hijacked-key")
	if err != nil {
		t.Fatalf("GetKey (hijacked) error: %v", err)
	}
	if hijacked != nil {
		t.Errorf("SECURITY BUG (TC-E54AB628): cross-org row test-org/hijacked-key was created via PK mutation")
		// Clean up the spurious row so the test doesn't leave dangling state.
		ormer.Engine.Delete(&Key{Owner: "test-org", Name: "hijacked-key"})
	}
}
