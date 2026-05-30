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
)

// seedTestKey inserts a key and returns a cleanup func.
func seedTestKey(t *testing.T, k *Key) func() {
	t.Helper()
	_, err := ormer.Engine.Insert(k)
	if err != nil {
		t.Fatalf("seedTestKey insert: %v", err)
	}
	return func() {
		_, _ = ormer.Engine.Delete(k)
	}
}

// TestUpdateKey_CredentialsAreImmutable guards TC-620B2050:
// POST /api/update-key must not allow an attacker to overwrite accessKey or accessSecret.
func TestUpdateKey_CredentialsAreImmutable(t *testing.T) {
	InitConfig()

	original := &Key{
		Owner:        "built-in",
		Name:         "test-immutable-creds",
		CreatedTime:  util.GetCurrentTime(),
		UpdatedTime:  util.GetCurrentTime(),
		DisplayName:  "Original",
		Type:         "Organization",
		Organization: "built-in",
		AccessKey:    "original-ak",
		AccessSecret: "original-secret",
		State:        "Active",
	}
	cleanup := seedTestKey(t, original)
	defer cleanup()

	// Attacker-supplied body: attempts to overwrite credentials.
	attackerKey := &Key{
		Owner:        "built-in",
		Name:         "test-immutable-creds",
		DisplayName:  "Tampered",
		Type:         "Organization",
		Organization: "built-in",
		AccessKey:    "hijacked-ak",
		AccessSecret: "hijacked-secret",
		State:        "Active",
	}

	_, err := UpdateKey("built-in/test-immutable-creds", attackerKey)
	if err != nil {
		t.Fatalf("UpdateKey error: %v", err)
	}

	stored, err := getKey("built-in", "test-immutable-creds")
	if err != nil {
		t.Fatalf("getKey error: %v", err)
	}

	if stored.AccessKey != original.AccessKey {
		t.Errorf("accessKey was overwritten: got %q, want %q", stored.AccessKey, original.AccessKey)
	}
	if stored.AccessSecret != original.AccessSecret {
		t.Errorf("accessSecret was overwritten: got %q, want %q", stored.AccessSecret, original.AccessSecret)
	}
}

// TestUpdateKey_TenantBindingIsImmutable guards TC-E9DA4A48:
// UpdateKey must not allow reassigning a key's organization, application, or user
// to values outside the key's original tenant.
func TestUpdateKey_TenantBindingIsImmutable(t *testing.T) {
	InitConfig()

	original := &Key{
		Owner:        "built-in",
		Name:         "test-tenant-immutable",
		CreatedTime:  util.GetCurrentTime(),
		UpdatedTime:  util.GetCurrentTime(),
		DisplayName:  "Original",
		Type:         "Application",
		Organization: "built-in",
		Application:  "app-built-in",
		User:         "",
		AccessKey:    "ak-tenant",
		AccessSecret: "secret-tenant",
		State:        "Active",
	}
	cleanup := seedTestKey(t, original)
	defer cleanup()

	// Attacker attempts to repoint key to a different tenant.
	attackerKey := &Key{
		Owner:        "built-in",
		Name:         "test-tenant-immutable",
		DisplayName:  "Tampered",
		Type:         "Organization",
		Organization: "attacker-org",
		Application:  "attacker-app",
		User:         "attacker-user",
		State:        "Active",
	}

	_, err := UpdateKey("built-in/test-tenant-immutable", attackerKey)
	if err != nil {
		t.Fatalf("UpdateKey error: %v", err)
	}

	stored, err := getKey("built-in", "test-tenant-immutable")
	if err != nil {
		t.Fatalf("getKey error: %v", err)
	}

	if stored.Organization != original.Organization {
		t.Errorf("organization was reassigned: got %q, want %q", stored.Organization, original.Organization)
	}
	if stored.Application != original.Application {
		t.Errorf("application was reassigned: got %q, want %q", stored.Application, original.Application)
	}
	if stored.User != original.User {
		t.Errorf("user was reassigned: got %q, want %q", stored.User, original.User)
	}
}

// TestUpdateKey_PreservesUnsentFields guards TC-D68AA548:
// A partial update body must not silently zero fields the client did not touch.
func TestUpdateKey_PreservesUnsentFields(t *testing.T) {
	InitConfig()

	original := &Key{
		Owner:        "built-in",
		Name:         "test-preserve-fields",
		CreatedTime:  "2026-01-01T00:00:00Z",
		UpdatedTime:  util.GetCurrentTime(),
		DisplayName:  "Keep This Name",
		Type:         "Application",
		Organization: "built-in",
		Application:  "app-built-in",
		AccessKey:    "ak-preserve",
		AccessSecret: "secret-preserve",
		State:        "Active",
	}
	cleanup := seedTestKey(t, original)
	defer cleanup()

	// Partial body: only changes State, omits DisplayName, Application, createdTime.
	partial := &Key{
		Owner:        "built-in",
		Name:         "test-preserve-fields",
		Type:         "Application",
		Organization: "built-in",
		State:        "Inactive",
		// DisplayName and Application intentionally absent (zero values)
	}

	_, err := UpdateKey("built-in/test-preserve-fields", partial)
	if err != nil {
		t.Fatalf("UpdateKey error: %v", err)
	}

	stored, err := getKey("built-in", "test-preserve-fields")
	if err != nil {
		t.Fatalf("getKey error: %v", err)
	}

	if stored.CreatedTime != original.CreatedTime {
		t.Errorf("createdTime was cleared: got %q, want %q", stored.CreatedTime, original.CreatedTime)
	}
	if stored.State != "Inactive" {
		t.Errorf("state was not updated: got %q, want %q", stored.State, "Inactive")
	}
}
