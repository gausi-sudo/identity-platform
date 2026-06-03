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

func seedTestKeys(t *testing.T) {
	t.Helper()
	keys := []*Key{
		{
			Owner:        "org-a",
			Name:         "key-a",
			CreatedTime:  util.GetCurrentTime(),
			UpdatedTime:  util.GetCurrentTime(),
			DisplayName:  "Key A",
			Type:         "Organization",
			Organization: "org-a",
			AccessKey:    "AK-ORGA",
			AccessSecret: "secret-org-a",
			State:        "Active",
		},
		{
			Owner:        "org-b",
			Name:         "key-b",
			CreatedTime:  util.GetCurrentTime(),
			UpdatedTime:  util.GetCurrentTime(),
			DisplayName:  "Key B",
			Type:         "Organization",
			Organization: "org-b",
			AccessKey:    "AK-ORGB",
			AccessSecret: "secret-org-b",
			State:        "Active",
		},
	}
	for _, k := range keys {
		_, _ = ormer.Engine.Insert(k)
	}
	t.Cleanup(func() {
		for _, k := range keys {
			_, _ = ormer.Engine.Delete(k)
		}
		// also clean up any cross-org relocation artifacts
		ormer.Engine.Delete(&Key{Owner: "org-b", Name: "stolen"})
	})
}

// TestGetMaskedKeyMasksAccessSecret verifies that GetMaskedKey — the helper
// used by the GetKey controller — always returns "***" for AccessSecret.
// Regression test for TC-2A9EFD80.
func TestGetMaskedKeyMasksAccessSecret(t *testing.T) {
	createDatabase = false
	InitConfig()
	seedTestKeys(t)

	raw, err := GetKey("org-a/key-a")
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	if raw == nil {
		t.Fatal("GetKey returned nil")
	}

	masked := GetMaskedKey(raw)
	if masked.AccessSecret != "***" {
		t.Errorf("GetMaskedKey exposed plaintext AccessSecret %q; want \"***\"", masked.AccessSecret)
	}
}

// TestUpdateKeyCannotRelocateToOtherOrg verifies that UpdateKey refuses to
// move a key to a different owner/name by supplying mismatched body fields.
// After the call the original row must still exist at its original PK.
// Regression test for TC-9AD8F5AD.
func TestUpdateKeyCannotRelocateToOtherOrg(t *testing.T) {
	createDatabase = false
	InitConfig()
	seedTestKeys(t)

	// Attempt cross-org relocation: target id = org-a/key-a but body says org-b/stolen.
	// UpdateKey must either return an error or leave the original row intact.
	relocated := &Key{
		Owner:        "org-b",
		Name:         "stolen",
		DisplayName:  "stolen",
		Type:         "Organization",
		Organization: "org-b",
		AccessKey:    "AK-STOLEN",
		AccessSecret: "PWNED",
		State:        "Active",
	}
	_, _ = UpdateKey("org-a/key-a", relocated) // error is acceptable; we check row state below

	// The original key must still exist at org-a/key-a regardless of whether UpdateKey errored.
	original, err := GetKey("org-a/key-a")
	if err != nil {
		t.Fatalf("GetKey after UpdateKey returned error: %v", err)
	}
	if original == nil {
		t.Error("UpdateKey relocated org-a/key-a to a different owner/name; the original row is gone — cross-org takeover is possible")
	}

	// The relocated row must NOT exist.
	stolen, err := getKey("org-b", "stolen")
	if err != nil {
		t.Fatalf("getKey(org-b, stolen) returned error: %v", err)
	}
	if stolen != nil {
		t.Error("UpdateKey created a row at org-b/stolen; cross-org relocation succeeded — this is a bug")
	}
}

// TestUpdateKeyDoesNotDestroySecret verifies that a benign update (e.g. renaming
// displayName) does not overwrite the stored AccessSecret with the masked
// sentinel "***" returned by GetMaskedKey/GetKey.
// Regression test for TC-660C532A.
func TestUpdateKeyDoesNotDestroySecret(t *testing.T) {
	createDatabase = false
	InitConfig()
	seedTestKeys(t)

	// Simulate the normal UI edit flow: GET masked key → mutate one field → POST update.
	maskedKey, err := GetKey("org-a/key-a")
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	maskedKey = GetMaskedKey(maskedKey) // AccessSecret is now "***"
	maskedKey.DisplayName = "Renamed"
	_, err = UpdateKey("org-a/key-a", maskedKey)
	if err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}

	// The real AccessSecret must survive intact in the database.
	raw, err := getKey("org-a", "key-a")
	if err != nil {
		t.Fatalf("getKey returned error: %v", err)
	}
	if raw == nil {
		t.Fatal("key disappeared after update")
	}
	if raw.AccessSecret == "***" {
		t.Error("UpdateKey overwrote the real AccessSecret with the masked sentinel \"***\"")
	}
	if raw.AccessSecret != "secret-org-a" {
		t.Errorf("UpdateKey changed AccessSecret to %q; want original value %q", raw.AccessSecret, "secret-org-a")
	}
}
