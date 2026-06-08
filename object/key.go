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
	"fmt"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

type Key struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`

	// Type indicates the scope this key belongs to: "Organization", "Application", or "User"
	Type         string `xorm:"varchar(100)" json:"type"`
	Organization string `xorm:"varchar(100)" json:"organization"`
	Application  string `xorm:"varchar(100)" json:"application"`
	User         string `xorm:"varchar(100)" json:"user"`

	AccessKey    string `xorm:"varchar(100) index" json:"accessKey"`
	AccessSecret string `xorm:"varchar(100)" json:"accessSecret"`

	ExpireTime string `xorm:"varchar(100)" json:"expireTime"`
	State      string `xorm:"varchar(100)" json:"state"`
}

func GetMaskedKey(key *Key) *Key {
	if key == nil {
		return nil
	}

	if key.AccessSecret != "" {
		key.AccessSecret = "***"
	}

	return key
}

func GetMaskedKeys(keys []*Key, err error) ([]*Key, error) {
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		key = GetMaskedKey(key)
	}
	return keys, nil
}

func GetKeyCount(owner string) (int64, error) {
	session := GetSession(owner, -1, -1, "", "", "", "")
	return session.Count(&Key{})
}

func GetKeys(owner string) ([]*Key, error) {
	keys := []*Key{}
	err := ormer.Engine.Desc("created_time").Find(&keys, &Key{Owner: owner})
	if err != nil {
		return keys, err
	}
	return keys, nil
}

func GetPaginationKeys(owner string, offset, limit int, sortField, sortOrder string) ([]*Key, error) {
	keys := []*Key{}
	sortField, err := getKeySortField(sortField)
	if err != nil {
		return keys, err
	}
	session := GetSession(owner, offset, limit, "", "", sortField, sortOrder)
	err = session.Find(&keys)
	if err != nil {
		return keys, err
	}
	return keys, nil
}

func getKeySortField(sortField string) (string, error) {
	if sortField == "" {
		return sortField, nil
	}

	allowedSortFields := map[string]string{
		"owner":       "owner",
		"name":        "name",
		"createdTime": "createdTime",
		"updatedTime": "updatedTime",
		"displayName": "displayName",
		"type":        "type",
		"accessKey":   "accessKey",
		"expireTime":  "expireTime",
		"state":       "state",
	}
	if field, ok := allowedSortFields[sortField]; ok {
		return field, nil
	}

	return "", fmt.Errorf("invalid key sort field")
}

func getKey(owner, name string) (*Key, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	key := Key{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&key)
	if err != nil {
		return &key, err
	}

	if existed {
		return &key, nil
	}
	return nil, nil
}

func GetKey(id string) (*Key, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getKey(owner, name)
}

func UpdateKey(id string, key *Key) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}
	oldKey, err := getKey(owner, name)
	if err != nil {
		return false, err
	} else if oldKey == nil {
		return false, nil
	}
	if key.Owner != owner || key.Name != name {
		return false, fmt.Errorf("key owner and name cannot be changed")
	}
	if key.Type != oldKey.Type || key.Organization != oldKey.Organization || key.Application != oldKey.Application || key.User != oldKey.User {
		return false, fmt.Errorf("key scope cannot be changed")
	}

	key.UpdatedTime = util.GetCurrentTime()
	if key.AccessSecret == "***" {
		key.AccessSecret = oldKey.AccessSecret
	}

	affected, err := ormer.Engine.ID(core.PK{owner, name}).
		AllCols().
		Omit("owner", "name", "type", "organization", "application", "user", "access_key", "access_secret").
		Update(key)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (key *Key) GetId() string {
	return fmt.Sprintf("%s/%s", key.Owner, key.Name)
}
