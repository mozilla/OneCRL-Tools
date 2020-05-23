/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package general

import "github.com/mozilla/OneCRL-Tools/bugzilla/api"

// https://bugzilla.readthedocs.io/en/latest/api/core/v1/general.html#basic-information
type Version struct {
	api.Ok
	api.Get
}

func (v *Version) Resource() string {
	return "/version"
}

type VersionResponse struct {
	Version string `json:"version"`
}
