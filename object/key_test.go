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

	"github.com/casdoor/casdoor/util"
)

func insertTestKey(t *testing.T, key *Key) {
	t.Helper()
	if key.CreatedTime == "" {
		key.CreatedTime = util.GetCurrentTime()
	}
	_, err := ormer.Engine.InsertOne(key)
	if err != nil {
		t.Fatalf("insert test key: %v", err)
	}
	t.Cleanup(func() {
		_, _ = ormer.Engine.Delete(&Key{Owner: key.Owner, Name: key.Name})
	})
}

// TestUpdateKeyDoesNotChangeSecret is a regression test for TC-767C6125.
// UpdateKey must not allow callers to overwrite accessKey or accessSecret.
// On unfixed code (AllCols): FAILS — the attacker-supplied secret is persisted.
// On fixed code (Cols whitelist): PASSES — secrets are preserved.
func TestUpdateKeyDoesNotChangeSecret(t *testing.T) {
	InitConfig()

	key := &Key{
		Owner:        "built-in",
		Name:         "test-regression-767c6125",
		AccessKey:    "ORIGINAL-AK",
		AccessSecret: "original-secret",
		State:        "Active",
	}
	insertTestKey(t, key)

	attacker := *key
	attacker.AccessKey = "HIJACKED-AK"
	attacker.AccessSecret = "hijacked-secret"
	attacker.DisplayName = "updated"

	if _, err := UpdateKey(key.Owner+"/"+key.Name, &attacker); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	got, err := getKey(key.Owner, key.Name)
	if err != nil {
		t.Fatalf("getKey: %v", err)
	}
	if got == nil {
		t.Fatal("key not found after update")
	}
	if got.AccessSecret != "original-secret" {
		t.Errorf("TC-767C6125: accessSecret overwritten: got %q, want %q", got.AccessSecret, "original-secret")
	}
	if got.AccessKey != "ORIGINAL-AK" {
		t.Errorf("TC-767C6125: accessKey overwritten: got %q, want %q", got.AccessKey, "ORIGINAL-AK")
	}
}

// TestUpdateKeyRejectsCrossOrgOwnerChange is a regression test for TC-B6AD9900.
// UpdateKey(id=org-a/key-a, body={owner:org-b, name:stolen}) must not move the
// row out of org-a or create it in org-b.
// On unfixed code (AllCols): FAILS — the PK columns are rewritten, moving the row.
// On fixed code (Cols whitelist): PASSES — owner/name are not updatable columns.
func TestUpdateKeyRejectsCrossOrgOwnerChange(t *testing.T) {
	InitConfig()

	key := &Key{
		Owner:        "built-in",
		Name:         "test-regression-b6ad9900",
		AccessKey:    "ORIGINAL-AK-CROSS",
		AccessSecret: "original-secret-cross",
		State:        "Active",
	}
	insertTestKey(t, key)
	// Also clean up any leaked row in test-org in case the unfixed code runs.
	t.Cleanup(func() {
		_, _ = ormer.Engine.Delete(&Key{Owner: "test-org", Name: "stolen-key"})
	})

	crossOrgKey := &Key{
		Owner:        "test-org",
		Name:         "stolen-key",
		AccessKey:    "STOLEN-AK",
		AccessSecret: "stolen-secret",
		DisplayName:  "STOLEN",
		State:        "Active",
	}

	if _, err := UpdateKey(key.Owner+"/"+key.Name, crossOrgKey); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	// Original row must still exist in built-in.
	original, err := getKey("built-in", "test-regression-b6ad9900")
	if err != nil {
		t.Fatalf("getKey original: %v", err)
	}
	if original == nil {
		t.Error("TC-B6AD9900: key was moved out of built-in — cross-org ownership change succeeded")
	}

	// Stolen name must NOT have appeared in test-org.
	stolen, err := getKey("test-org", "stolen-key")
	if err != nil {
		t.Fatalf("getKey stolen: %v", err)
	}
	if stolen != nil {
		t.Error("TC-B6AD9900: key appeared in test-org/stolen-key — cross-org move succeeded")
	}
}
