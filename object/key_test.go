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

func seedTestKey(t *testing.T) (*Key, func()) {
	t.Helper()
	key := &Key{
		Owner:        "built-in",
		Name:         "pentest-regression-key",
		CreatedTime:  "2026-01-01T00:00:00Z",
		DisplayName:  "Regression Test Key",
		Type:         "Organization",
		Organization: "built-in",
		AccessKey:    "AK-REGRESSION",
		AccessSecret: "original-secret-value",
		ExpireTime:   "2099-12-31T23:59:59Z",
		State:        "Active",
	}
	_, err := ormer.Engine.Insert(key)
	if err != nil {
		t.Fatalf("failed to insert test key: %v", err)
	}
	cleanup := func() {
		ormer.Engine.Delete(&Key{Owner: key.Owner, Name: key.Name})
	}
	return key, cleanup
}

// TC-26E61CAE: UpdateKey must not allow callers to overwrite accessKey or accessSecret.
// The UI marks these fields readOnly; the server must enforce the same invariant.
func TestUpdateKeyDoesNotOverwriteAccessSecret(t *testing.T) {
	InitConfig()

	original, cleanup := seedTestKey(t)
	defer cleanup()

	// Attempt to inject an attacker-chosen secret via UpdateKey.
	attacker := &Key{
		Owner:        original.Owner,
		Name:         original.Name,
		DisplayName:  "modified-display",
		AccessKey:    "AK-INJECTED",
		AccessSecret: "attacker-chosen-secret",
		State:        "Active",
	}
	ok, err := UpdateKey(original.Owner+"/"+original.Name, attacker)
	if err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}
	if !ok {
		t.Fatal("UpdateKey reported no rows affected")
	}

	fetched, err := GetKey(original.Owner + "/" + original.Name)
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	if fetched.AccessSecret == "attacker-chosen-secret" {
		t.Error("FAIL TC-26E61CAE: accessSecret was overwritten via UpdateKey — secret injection vulnerability present")
	}
	if fetched.AccessKey == "AK-INJECTED" {
		t.Error("FAIL TC-26E61CAE: accessKey was overwritten via UpdateKey")
	}
}

// TC-9E3A3A65: UpdateKey must not allow rebinding the key's identity (type, organization,
// application, user) — those are immutable after creation. Only metadata (displayName,
// expireTime, state) should be editable.
func TestUpdateKeyDoesNotRebindIdentityFields(t *testing.T) {
	InitConfig()

	original, cleanup := seedTestKey(t)
	defer cleanup()

	// Attempt to rebind user from original owner to a different identity.
	rebind := &Key{
		Owner:        original.Owner,
		Name:         original.Name,
		DisplayName:  "rebind-attempt",
		Type:         "Application",
		Organization: "built-in",
		Application:  "app-built-in",
		User:         "carol",
	}
	ok, err := UpdateKey(original.Owner+"/"+original.Name, rebind)
	if err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}
	if !ok {
		t.Fatal("UpdateKey reported no rows affected")
	}

	fetched, err := GetKey(original.Owner + "/" + original.Name)
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	if fetched.Type != original.Type {
		t.Errorf("FAIL TC-9E3A3A65: type was rebound from %q to %q", original.Type, fetched.Type)
	}
	if fetched.Organization != original.Organization {
		t.Errorf("FAIL TC-9E3A3A65: organization was rebound from %q to %q", original.Organization, fetched.Organization)
	}
	if fetched.Application != original.Application {
		t.Errorf("FAIL TC-9E3A3A65: application was rebound from %q to %q", original.Application, fetched.Application)
	}
	if fetched.User != original.User {
		t.Errorf("FAIL TC-9E3A3A65: user was rebound from %q to %q", original.User, fetched.User)
	}
}

// TC-6C65DEB6: UpdateKey with a partial body must not wipe fields the caller omitted.
// Sending only owner+name+displayName must not zero out createdTime, expireTime, or state.
func TestUpdateKeyDoesNotWipeOmittedFields(t *testing.T) {
	InitConfig()

	original, cleanup := seedTestKey(t)
	defer cleanup()

	// Partial update: only send owner, name, and displayName — omit everything else.
	partial := &Key{
		Owner:       original.Owner,
		Name:        original.Name,
		DisplayName: "only-display-name-sent",
	}
	ok, err := UpdateKey(original.Owner+"/"+original.Name, partial)
	if err != nil {
		t.Fatalf("UpdateKey returned error: %v", err)
	}
	if !ok {
		t.Fatal("UpdateKey reported no rows affected")
	}

	fetched, err := GetKey(original.Owner + "/" + original.Name)
	if err != nil {
		t.Fatalf("GetKey returned error: %v", err)
	}
	if fetched.CreatedTime == "" {
		t.Error("FAIL TC-6C65DEB6: createdTime was wiped to empty — audit timestamp destroyed")
	}
	if fetched.ExpireTime == "" {
		t.Error("FAIL TC-6C65DEB6: expireTime was wiped to empty — key effectively un-expired")
	}
	if fetched.State == "" {
		t.Error("FAIL TC-6C65DEB6: state was wiped to empty")
	}
	if fetched.AccessKey == "" {
		t.Error("FAIL TC-6C65DEB6: accessKey was wiped to empty")
	}
}
