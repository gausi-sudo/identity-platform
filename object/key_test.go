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
	"strings"
	"testing"
)

// Regression test for TC-810F0660: UpdateKey must reject a request where the
// body's owner field doesn't match the owner in the id query param, preventing
// cross-org IDOR via the POST body owner/id mismatch.
func TestUpdateKeyRejectsOwnerMismatch(t *testing.T) {
	InitConfig()

	key := &Key{
		Owner:        "attacker-org",
		Name:         "victim-key",
		AccessKey:    "attacker-controlled",
		AccessSecret: "attacker-controlled-secret",
		State:        "Active",
	}
	_, err := UpdateKey("victim-org/victim-key", key)
	if err == nil {
		t.Fatal("UpdateKey must return an error when body owner does not match id owner")
	}
	if !strings.Contains(err.Error(), "owner") {
		t.Fatalf("expected an owner-mismatch error, got: %v", err)
	}
}

// Regression test for TC-1072A83B: UpdateKey must not allow overwriting
// accessKey or accessSecret, even when those fields are present in the
// request body. Only safe metadata fields (displayName, type, etc.) should
// be mutable via this endpoint.
func TestUpdateKeyDoesNotOverwriteCredentials(t *testing.T) {
	InitConfig()

	original := &Key{
		Owner:        "built-in",
		Name:         "test-mass-assign-key",
		AccessKey:    "ORIGINAL-AK-DO-NOT-CHANGE",
		AccessSecret: "original-secret-do-not-change",
		DisplayName:  "Original",
		State:        "Active",
	}
	if _, err := ormer.Engine.InsertOne(original); err != nil {
		t.Fatalf("failed to insert test key: %v", err)
	}
	defer ormer.Engine.Delete(&Key{Owner: "built-in", Name: "test-mass-assign-key"})

	update := &Key{
		Owner:        "built-in",
		Name:         "test-mass-assign-key",
		AccessKey:    "ATTACKER-CHOSEN-AK",
		AccessSecret: "attacker-chosen-secret",
		DisplayName:  "Updated Display Name",
		State:        "Active",
	}
	affected, err := UpdateKey("built-in/test-mass-assign-key", update)
	if err != nil {
		t.Fatalf("UpdateKey returned unexpected error: %v", err)
	}
	if !affected {
		t.Fatal("UpdateKey should have updated the row")
	}

	stored, err := GetKey("built-in/test-mass-assign-key")
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	if stored.AccessKey != "ORIGINAL-AK-DO-NOT-CHANGE" {
		t.Errorf("accessKey was overwritten: got %q, want %q", stored.AccessKey, "ORIGINAL-AK-DO-NOT-CHANGE")
	}
	if stored.AccessSecret != "original-secret-do-not-change" {
		t.Errorf("accessSecret was overwritten: got %q, want %q", stored.AccessSecret, "original-secret-do-not-change")
	}
	if stored.DisplayName != "Updated Display Name" {
		t.Errorf("displayName was not updated: got %q, want %q", stored.DisplayName, "Updated Display Name")
	}
}
