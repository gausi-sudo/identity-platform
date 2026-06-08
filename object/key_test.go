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

	"github.com/xorm-io/xorm"
)

func TestGetMaskedKey(t *testing.T) {
	key := &Key{AccessKey: "access-key", AccessSecret: "access-secret"}

	maskedKey := GetMaskedKey(key)
	if maskedKey.AccessKey != "access-key" {
		t.Fatalf("expected access key to remain unchanged, got: %s", maskedKey.AccessKey)
	}
	if maskedKey.AccessSecret != "***" {
		t.Fatalf("expected access secret to be masked, got: %s", maskedKey.AccessSecret)
	}
}

func TestUpdateKeyRejectsOwnerNamePivot(t *testing.T) {
	setupTestKeyOrmer(t)

	_, err := ormer.Engine.Insert(&Key{
		Owner:        "built-in",
		Name:         "prod-signing-key",
		DisplayName:  "Prod Signing Key",
		Type:         "Organization",
		Organization: "built-in",
		Application:  "app-built-in",
		User:         "admin",
		AccessKey:    "AK-BUILTIN-PROD",
		AccessSecret: "prod-secret",
		State:        "Active",
	})
	if err != nil {
		t.Fatal(err)
	}

	affected, err := UpdateKey("built-in/prod-signing-key", &Key{
		Owner:        "test-org",
		Name:         "pivot-prod-signing-key",
		DisplayName:  "Pivoted Key",
		Type:         "Organization",
		Organization: "test-org",
		Application:  "app-built-in",
		User:         "admin",
		AccessKey:    "AK-BUILTIN-PROD",
		AccessSecret: "***",
		State:        "Active",
	})
	if err == nil && affected {
		t.Fatalf("expected owner/name pivot update to be rejected")
	}

	originalKey, err := getKey("built-in", "prod-signing-key")
	if err != nil {
		t.Fatal(err)
	}
	if originalKey == nil {
		t.Fatalf("expected original key to remain under built-in/prod-signing-key")
	}
	if originalKey.AccessSecret != "prod-secret" {
		t.Fatalf("expected original access secret to remain unchanged, got: %s", originalKey.AccessSecret)
	}

	pivotKey, err := getKey("test-org", "pivot-prod-signing-key")
	if err != nil {
		t.Fatal(err)
	}
	if pivotKey != nil {
		t.Fatalf("expected no pivot key to be created, got: %+v", pivotKey)
	}
}

func TestUpdateKeyPreservesCredentialFields(t *testing.T) {
	setupTestKeyOrmer(t)

	_, err := ormer.Engine.Insert(&Key{
		Owner:        "test-org",
		Name:         "alice-api-key",
		DisplayName:  "Alice API Key",
		Type:         "User",
		Organization: "test-org",
		Application:  "app-test-org",
		User:         "alice",
		AccessKey:    "AK-TESTORG-ALICE",
		AccessSecret: "alice-secret",
		State:        "Active",
	})
	if err != nil {
		t.Fatal(err)
	}

	affected, err := UpdateKey("test-org/alice-api-key", &Key{
		Owner:        "test-org",
		Name:         "alice-api-key",
		DisplayName:  "Renamed Alice API Key",
		Type:         "User",
		Organization: "test-org",
		Application:  "app-test-org",
		User:         "alice",
		AccessKey:    "AK-TESTORG-ALICE-TEMP",
		AccessSecret: "changed-secret",
		State:        "Inactive",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !affected {
		t.Fatalf("expected editable key metadata update to affect the row")
	}

	key, err := getKey("test-org", "alice-api-key")
	if err != nil {
		t.Fatal(err)
	}
	if key.AccessKey != "AK-TESTORG-ALICE" {
		t.Fatalf("expected access key to remain unchanged, got: %s", key.AccessKey)
	}
	if key.AccessSecret != "alice-secret" {
		t.Fatalf("expected access secret to remain unchanged, got: %s", key.AccessSecret)
	}
	if key.DisplayName != "Renamed Alice API Key" {
		t.Fatalf("expected display name to update, got: %s", key.DisplayName)
	}
	if key.State != "Inactive" {
		t.Fatalf("expected state to update, got: %s", key.State)
	}
}

func TestGetPaginationKeysRejectsUnsupportedSortField(t *testing.T) {
	setupTestKeyOrmer(t)

	_, err := ormer.Engine.Insert(&Key{
		Owner:        "test-org",
		Name:         "alice-api-key",
		DisplayName:  "Alice API Key",
		Type:         "User",
		Organization: "test-org",
		Application:  "app-test-org",
		User:         "alice",
		AccessKey:    "AK-TESTORG-ALICE",
		AccessSecret: "alice-secret",
		State:        "Active",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = GetPaginationKeys("test-org", 0, 10, "sqlite_version()", "ascend")
	if err == nil {
		t.Fatalf("expected unsupported sort field to be rejected")
	}
	if err.Error() != "invalid key sort field" {
		t.Fatalf("expected generic invalid sort error, got: %s", err.Error())
	}
}

func setupTestKeyOrmer(t *testing.T) {
	t.Helper()

	engine, err := xorm.NewEngine("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Sync2(new(Key)); err != nil {
		t.Fatal(err)
	}

	oldOrmer := ormer
	ormer = &Ormer{Engine: engine}
	t.Cleanup(func() {
		ormer = oldOrmer
		_ = engine.Close()
	})
}
