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
	"github.com/xorm-io/xorm/names"
	_ "modernc.org/sqlite"
)

// initKeyTestOrmer sets up an in-memory SQLite engine scoped to one test.
func initKeyTestOrmer(t *testing.T) {
	t.Helper()
	engine, err := xorm.NewEngine("sqlite", "file::memory:?cache=shared&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	if err := engine.Sync2(new(Key)); err != nil {
		t.Fatalf("failed to sync Key table: %v", err)
	}
	ormer = &Ormer{Engine: engine}
	t.Cleanup(func() { engine.Close() })
}

// insertTestKey writes a key directly to the DB, bypassing UpdateKey.
func insertTestKey(t *testing.T, key *Key) {
	t.Helper()
	if _, err := ormer.Engine.Insert(key); err != nil {
		t.Fatalf("failed to insert test key: %v", err)
	}
}

// TC-839B1EAE regression: UpdateKey must not let callers overwrite accessKey or
// accessSecret, and must not silently wipe fields they omit from the request body.
func TestUpdateKeyDoesNotOverwriteCredentials(t *testing.T) {
	initKeyTestOrmer(t)

	original := &Key{
		Owner:        "test-org",
		Name:         "alice-api-key",
		CreatedTime:  "2026-02-20T09:30:00Z",
		DisplayName:  "Alice API Key",
		Application:  "app-test-org",
		AccessKey:    "AK-ORIGINAL",
		AccessSecret: "original-secret",
		State:        "Active",
	}
	insertTestKey(t, original)

	// Simulate an attacker-controlled update body: attacker-chosen credentials,
	// omitted DisplayName / CreatedTime / Application (would be empty strings).
	attackerUpdate := &Key{
		Owner:        "test-org",
		Name:         "alice-api-key",
		AccessKey:    "AK-ATTACKER-CHOSEN",
		AccessSecret: "attacker-secret",
		State:        "Active",
	}

	ok, err := UpdateKey("test-org/alice-api-key", attackerUpdate)
	if err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}
	if !ok {
		t.Fatal("UpdateKey reported no affected rows")
	}

	got, err := GetKey("test-org/alice-api-key")
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	if got == nil {
		t.Fatal("GetKey returned nil after update")
	}

	// Credential/provenance fields must never be touched by an update call.
	if got.AccessKey != original.AccessKey {
		t.Errorf("accessKey overwritten: want %q, got %q", original.AccessKey, got.AccessKey)
	}
	if got.AccessSecret != original.AccessSecret {
		t.Errorf("accessSecret overwritten: want %q, got %q", original.AccessSecret, got.AccessSecret)
	}
	if got.CreatedTime != original.CreatedTime {
		t.Errorf("createdTime silently wiped: want %q, got %q", original.CreatedTime, got.CreatedTime)
	}

	// Mutable metadata fields omitted from the update body must retain stored values.
	if got.DisplayName != original.DisplayName {
		t.Errorf("displayName silently wiped: want %q, got %q", original.DisplayName, got.DisplayName)
	}
	if got.Application != original.Application {
		t.Errorf("application silently wiped: want %q, got %q", original.Application, got.Application)
	}
}
