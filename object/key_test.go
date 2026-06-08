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

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

// TestUpdateKeyPKImmutability verifies that UpdateKey cannot be used to move a
// key record to a different (owner, name) pair via mass-assignment in the body.
// Regression test for TC-EBEAF201: AllCols().Update(key) wrote the composite PK
// fields from the untrusted JSON body, allowing cross-org record relocation.
func TestUpdateKeyPKImmutability(t *testing.T) {
	InitConfig()

	src := &Key{
		Owner:       "built-in",
		Name:        "test-pk-immutability-src",
		DisplayName: "Source",
		State:       "Active",
		CreatedTime: util.GetCurrentTime(),
	}
	if _, err := ormer.Engine.Insert(src); err != nil {
		t.Fatalf("insert source key: %v", err)
	}
	t.Cleanup(func() {
		ormer.Engine.ID(core.PK{"built-in", "test-pk-immutability-src"}).Delete(&Key{})
		ormer.Engine.ID(core.PK{"built-in", "test-pk-immutability-hijacked"}).Delete(&Key{})
	})

	// Body supplies a different owner/name — a mass-assignment attempt.
	body := &Key{
		Owner:       "built-in",
		Name:        "test-pk-immutability-hijacked",
		DisplayName: "HIJACKED",
		State:       "Inactive",
	}

	if _, err := UpdateKey("built-in/test-pk-immutability-src", body); err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}

	// Original record must still exist at its original location.
	got, err := getKey("built-in", "test-pk-immutability-src")
	if err != nil {
		t.Fatalf("getKey source: %v", err)
	}
	if got == nil {
		t.Error("TC-EBEAF201 regression: UpdateKey destroyed the source record via PK mass-assignment")
	}

	// No record must have been created at the attacker-controlled location.
	ghost, err := getKey("built-in", "test-pk-immutability-hijacked")
	if err != nil {
		t.Fatalf("getKey hijacked: %v", err)
	}
	if ghost != nil {
		t.Error("TC-EBEAF201 regression: UpdateKey created a new record at the attacker-controlled name")
	}
}
