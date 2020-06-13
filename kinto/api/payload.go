/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package api

import (
	"github.com/mozilla/OneCRL-Tools/kinto/api/authz"
)

type Payload struct {
	Data        interface{}        `json:"data"`
	Permissions *authz.Permissions `json:"permissions,omitempty"`
}

func NewPayload(data interface{}, perms *authz.Permissions) *Payload {
	return &Payload{
		Data:        data,
		Permissions: perms,
	}
}
