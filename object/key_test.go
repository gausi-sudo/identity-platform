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

// TestGetMaskedKeyRedactsSecret verifies that GetMaskedKey returns "***" for
// the access secret instead of the plaintext value.
// Regression test for TC-DD51C276 (accessSecret leak in single-key read).
func TestGetMaskedKeyRedactsSecret(t *testing.T) {
	createDatabase = false
	InitConfig()

	key := &Key{
		Owner:        "built-in",
		Name:         "regrtest-masked",
		AccessKey:    "AK-MASKED",
		AccessSecret: "real-secret-value",
		State:        "Active",
	}
	_, err := ormer.Engine.Insert(key)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	defer ormer.Engine.Delete(&Key{Owner: "built-in", Name: "regrtest-masked"})

	masked, err := GetMaskedKey("built-in/regrtest-masked")
	if err != nil {
		t.Fatalf("GetMaskedKey: %v", err)
	}
	if masked == nil {
		t.Fatal("GetMaskedKey returned nil")
	}
	if masked.AccessSecret != "***" {
		t.Fatalf("FAIL: accessSecret not masked, got %q", masked.AccessSecret)
	}
}

// TestUpdateKeyCannotRelocateOwner verifies that UpdateKey pins the PK from the
// id argument and ignores owner/name fields in the supplied key struct.
// Regression test for TC-249E613F (cross-org key takeover via PK hijack).
func TestUpdateKeyCannotRelocateOwner(t *testing.T) {
	createDatabase = false
	InitConfig()

	orig := &Key{
		Owner:        "built-in",
		Name:         "regrtest-orig",
		DisplayName:  "Original",
		AccessKey:    "AK-ORIG",
		AccessSecret: "secret-orig",
		State:        "Active",
	}
	_, err := ormer.Engine.Insert(orig)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	defer ormer.Engine.Delete(&Key{Owner: "built-in", Name: "regrtest-orig"})
	defer ormer.Engine.Delete(&Key{Owner: "attacker-org", Name: "regrtest-pivot"})

	// Attacker supplies a body with a different owner/name than the ?id.
	malicious := &Key{
		Owner:        "attacker-org",
		Name:         "regrtest-pivot",
		DisplayName:  "PWNED",
		AccessKey:    "AK-PWNED",
		AccessSecret: "pwned-secret",
		State:        "Active",
	}
	_, err = UpdateKey("built-in/regrtest-orig", malicious)
	if err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	// The original row must still exist in built-in.
	existing, err := getKey("built-in", "regrtest-orig")
	if err != nil {
		t.Fatalf("getKey built-in: %v", err)
	}
	if existing == nil {
		t.Fatal("FAIL: original key was deleted — PK hijack succeeded")
	}

	// No row should have been created under attacker-org.
	hijacked, err := getKey("attacker-org", "regrtest-pivot")
	if err != nil {
		t.Fatalf("getKey attacker-org: %v", err)
	}
	if hijacked != nil {
		t.Fatal("FAIL: key appeared under attacker-org — cross-org takeover succeeded")
	}
}
