/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package kintosigner

type Status struct {
	Data KintoStatus `json:"data"`
}

type KintoStatus struct {
	Status string `json:"status"`
}

func (s *Status) InReview() bool {
	return s.Data.Status == "to-review"
}

func WIP() Status {
	return Status{Data: KintoStatus{Status: "work-in-progress"}}
}

func ToReview() Status {
	return Status{Data: KintoStatus{Status: "to-review"}}
}

func ToSign() Status {
	return Status{Data: KintoStatus{Status: "to-sign"}}
}

func Signed() Status {
	return Status{Data: KintoStatus{Status: "signed"}}
}

func ToRollback() Status {
	return Status{Data: KintoStatus{Status: "to-rollback"}}
}

func ToResign() Status {
	return Status{Data: KintoStatus{Status: "to-resign"}}
}
