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

// TC-909BE802: GetMaskedKey must redact AccessSecret.
// Pre-fix: compilation fails because GetMaskedKey does not exist.
// Post-fix: passes because GetMaskedKey returns "***" for AccessSecret.
func TestGetMaskedKeyRedactsSecret(t *testing.T) {
	key := &Key{
		Owner:        "test",
		Name:         "my-key",
		AccessKey:    "AK-12345",
		AccessSecret: "real-secret-material",
	}
	masked := GetMaskedKey(key)
	if masked.AccessSecret != "***" {
		t.Errorf("GetMaskedKey: AccessSecret = %q, want \"***\"", masked.AccessSecret)
	}
	if masked.AccessKey != key.AccessKey {
		t.Errorf("GetMaskedKey: AccessKey should be unchanged, got %q", masked.AccessKey)
	}
	// Verify original is not mutated
	if key.AccessSecret != "real-secret-material" {
		t.Errorf("GetMaskedKey must not mutate the original key")
	}
}

// TC-E8E9E212: UpdateKey must not allow callers to overwrite AccessKey or AccessSecret.
// Pre-fix: AllCols().Update writes attacker-chosen credentials to the DB.
// Post-fix: explicit Cols() list excludes access_key and access_secret.
func TestUpdateKeyPreservesCredentials(t *testing.T) {
	InitConfig()

	const owner = "built-in"
	const name = "regression-cred-key"

	original := &Key{
		Owner:        owner,
		Name:         name,
		AccessKey:    "original-ak",
		AccessSecret: "original-secret",
		State:        "Active",
		DisplayName:  "Before",
	}
	_, err := ormer.Engine.Insert(original)
	if err != nil {
		t.Fatalf("setup: insert key: %v", err)
	}
	t.Cleanup(func() {
		ormer.Engine.Delete(&Key{Owner: owner, Name: name})
	})

	update := &Key{
		Owner:        owner,
		Name:         name,
		DisplayName:  "After",
		AccessKey:    "attacker-ak",
		AccessSecret: "attacker-secret",
		State:        "Active",
	}
	_, err = UpdateKey(owner+"/"+name, update)
	if err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	stored, err := getKey(owner, name)
	if err != nil {
		t.Fatalf("getKey after update: %v", err)
	}
	if stored == nil {
		t.Fatal("key not found after update")
	}
	if stored.AccessKey != "original-ak" {
		t.Errorf("TC-E8E9E212: AccessKey was overwritten to %q, want %q", stored.AccessKey, "original-ak")
	}
	if stored.AccessSecret != "original-secret" {
		t.Errorf("TC-E8E9E212: AccessSecret was overwritten to %q, want %q", stored.AccessSecret, "original-secret")
	}
}

// TC-C0CFBF0D (object layer): UpdateKey must not let a body with a different owner
// rename/move a key's PK across organizations.
// Pre-fix: AllCols().Update overwrites owner/name columns, destroying the original row.
// Post-fix: owner and name are pinned to the URL id; the original row is preserved.
//
// Note: the authz-filter half of TC-C0CFBF0D (Casbin reads owner from the JSON body
// instead of the URL ?id=) cannot be covered by a unit test — it requires the full
// HTTP stack (beego router + authz_filter + controller + object). Niro's post-fix
// re-run verifies that part end-to-end.
func TestUpdateKeyPreservesOwnership(t *testing.T) {
	InitConfig()

	const builtinOwner = "built-in"
	const name = "regression-ownership-key"

	builtinKey := &Key{
		Owner:        builtinOwner,
		Name:         name,
		AccessKey:    "ak-builtin",
		AccessSecret: "secret-builtin",
		State:        "Active",
	}
	_, err := ormer.Engine.Insert(builtinKey)
	if err != nil {
		t.Fatalf("setup: insert built-in key: %v", err)
	}
	t.Cleanup(func() {
		ormer.Engine.Delete(&Key{Owner: builtinOwner, Name: name})
		ormer.Engine.Delete(&Key{Owner: "test-org", Name: name}) // clean up if it moved
	})

	// Caller sends body with owner="test-org" but URL id targets "built-in/<name>"
	hijackBody := &Key{
		Owner:        "test-org",
		Name:         name,
		AccessKey:    "ak-hijacked",
		AccessSecret: "secret-hijacked",
		State:        "Active",
	}
	_, _ = UpdateKey(builtinOwner+"/"+name, hijackBody)

	stored, err := getKey(builtinOwner, name)
	if err != nil {
		t.Fatalf("getKey after update: %v", err)
	}
	if stored == nil {
		t.Errorf("TC-C0CFBF0D: built-in/%s was destroyed (moved to test-org namespace) — cross-org takeover confirmed", name)
	}
}
