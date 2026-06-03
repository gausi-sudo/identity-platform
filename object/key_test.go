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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xorm-io/xorm"
	_ "modernc.org/sqlite"
)

// newTestOrmer creates an in-memory SQLite engine with the Key table for unit tests.
func newTestOrmer(t *testing.T) *Ormer {
	t.Helper()
	engine, err := xorm.NewEngine("sqlite", ":memory:")
	require.NoError(t, err)
	err = engine.Sync2(new(Key))
	require.NoError(t, err)
	o := &Ormer{Engine: engine}
	t.Cleanup(func() { engine.Close() })
	return o
}

// TestUpdateKey_PreservesBindingFields is a regression test for TC-56B9341A.
// An org-scoped caller must not be able to rebind Organization, Application,
// or User to values outside the key owner's tenant boundary.
func TestUpdateKey_PreservesBindingFields(t *testing.T) {
	saved := ormer
	ormer = newTestOrmer(t)
	t.Cleanup(func() { ormer = saved })

	// Seed: a key whose binding fields all live inside "owner-org".
	seed := &Key{
		Owner:        "owner-org",
		Name:         "test-key",
		CreatedTime:  "2026-01-01T00:00:00Z",
		DisplayName:  "Test Key",
		Type:         "User",
		Organization: "owner-org",
		Application:  "app-owner-org",
		User:         "owner-org/alice",
		AccessKey:    "AK-TEST",
		AccessSecret: "SK-TEST",
		State:        "Active",
	}
	_, err := ormer.Engine.InsertOne(seed)
	require.NoError(t, err)

	// Attempt to rebind to a different tenant (the cross-tenant attack).
	update := &Key{
		Owner:        "owner-org",
		Name:         "test-key",
		DisplayName:  "hijacked",
		Type:         "User",
		Organization: "attacker-org",  // cross-tenant
		Application:  "attacker-app",  // cross-tenant
		User:         "attacker-user", // cross-tenant
		AccessKey:    "AK-TEST",
		AccessSecret: "SK-TEST",
		State:        "Active",
	}
	affected, err := UpdateKey("owner-org/test-key", update)
	require.NoError(t, err)
	require.True(t, affected)

	// Read back: Organization/Application/User must be unchanged.
	got, err := GetKey("owner-org/test-key")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, "owner-org", got.Organization, "Organization must not be rebound cross-tenant (TC-56B9341A)")
	assert.Equal(t, "app-owner-org", got.Application, "Application must not be rebound cross-tenant (TC-56B9341A)")
	assert.Equal(t, "owner-org/alice", got.User, "User must not be rebound cross-tenant (TC-56B9341A)")
}
