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

// TestUpdateKeyCannotRelocate is a regression test for TC-3A6DDA9A.
// UpdateKey must lock owner/name to the values in the id parameter so a
// caller cannot move the row to a different org by supplying different PK
// values in the Key struct (AllCols() would otherwise rewrite the PK).
func TestUpdateKeyCannotRelocate(t *testing.T) {
	InitConfig()

	const owner = "built-in"
	const name = "test-relocation-key"

	// Clean up any rows left by a previous aborted run of this test.
	ormer.Engine.Delete(&Key{Owner: owner, Name: name})
	ormer.Engine.Delete(&Key{Owner: "attacker-org", Name: "hijacked"})

	// Seed a key directly in the DB.
	seed := &Key{
		Owner:        owner,
		Name:         name,
		DisplayName:  "Relocation test",
		AccessKey:    "AK-RELOC-TEST",
		AccessSecret: "secret-original",
		State:        "Active",
	}
	_, err := ormer.Engine.Insert(seed)
	if err != nil {
		t.Fatalf("failed to insert seed key: %v", err)
	}
	// Also clean up any stale relocated row from a previous failed run.
	defer ormer.Engine.Delete(&Key{Owner: "attacker-org", Name: "hijacked"})
	defer ormer.Engine.Delete(seed)

	// Attempt to relocate the key by passing a Key struct whose Owner and
	// Name differ from the id.  Before the fix, AllCols() would overwrite
	// the PK and the row would appear under "attacker-org/hijacked".
	relocated := &Key{
		Owner:        "attacker-org",
		Name:         "hijacked",
		DisplayName:  "Hijacked",
		AccessKey:    "AK-RELOC-TEST",
		AccessSecret: "secret-pwned",
		State:        "Active",
	}
	_, updateErr := UpdateKey(owner+"/"+name, relocated)
	if updateErr != nil {
		t.Fatalf("UpdateKey returned unexpected error: %v", updateErr)
	}

	// The original row must still exist with the original owner/name.
	got, err := getKey(owner, name)
	if err != nil {
		t.Fatalf("getKey after update error: %v", err)
	}
	if got == nil {
		t.Fatal("TC-3A6DDA9A regression: key was relocated — original row gone after UpdateKey with mismatched owner/name in body")
	}
	if got.Owner != owner || got.Name != name {
		t.Fatalf("TC-3A6DDA9A regression: key owner/name changed to %s/%s", got.Owner, got.Name)
	}

	// The relocated row must NOT exist.
	bad, err := getKey("attacker-org", "hijacked")
	if err != nil {
		t.Fatalf("getKey for relocated row error: %v", err)
	}
	if bad != nil {
		t.Fatal("TC-3A6DDA9A regression: key was duplicated/relocated to attacker-org/hijacked")
	}
}
