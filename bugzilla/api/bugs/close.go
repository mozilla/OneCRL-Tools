/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package bugs

// Invalidate set the status of the target bug to RESOLVED
// with the resolution INVALID and posts the provided comment
// as an explanation for the resolution.
func Invalidate(bug int, comment string) *Update {
	return &Update{Id: bug, Status: "RESOLVED", Resolution: "INVALID", Comment: &Comment{Body: comment}}
}
