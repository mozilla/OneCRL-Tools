/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package authz

// https://docs.kinto-storage.org/en/stable/api/1.x/permissions.html#api-principals
type Permissions struct {
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
}

const (
	world         = "system.Everyone"
	authenticated = "system.Authenticated"
)

var WorldR = &Permissions{Read: []string{world}}
var WorldRW = &Permissions{Write: []string{world}, Read: []string{world}}
