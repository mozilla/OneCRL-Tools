/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package bugs

import (
	"fmt"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api"
)

// https://bugzilla.readthedocs.io/en/latest/api/core/v1/bug.html#update-bug
type Update struct {
	Id int `json:"-"`
	api.Put
	api.Ok
	Ids                 []int               `json:"ids,omitempty"`
	Alias               *AddRemoveSetString `json:"alias,omitempty"`
	AssignedTo          string              `json:"assigned_to,omitempty"`
	Blocks              []AddRemoveSetInt   `json:"blocks,omitempty"`
	DependsOn           []AddRemoveSetInt   `json:"depends_on,omitempty"`
	Cc                  *AddRemoveString    `json:"cc,omitempty"`
	IsCcAccessible      bool                `json:"is_cc_accessible,omitempty"`
	Comment             *Comment            `json:"comment,omitempty"`
	CommentIsPrivate    map[int]bool        `json:"comment_is_private,omitempty"`
	CommentTags         []string            `json:"comment_tags,omitempty"`
	Component           string              `json:"component,omitempty"`
	Deadline            string              `json:"deadline,omitempty"`
	DupeOf              int                 `json:"dupe_of,omitempty"`
	EstimatedTime       int64               `json:"estimated_time,omitempty"`
	Flags               []UpdateFlag        `json:"flags,omitempty"`
	Groups              *AddRemoveString    `json:"groups,omitempty"`
	Keywords            *AddRemoveSetString `json:"keywords,omitempty"`
	OpSys               string              `json:"op_sys,omitempty"`
	Platform            string              `json:"platform,omitempty"`
	Priority            string              `json:"priority,omitempty"`
	Product             string              `json:"product,omitempty"`
	QaContact           string              `json:"qa_contact,omitempty"`
	IsCreatorAccessible bool                `json:"is_creator_accessible,omitempty"`
	RemainingTime       int64               `json:"remaining_time,omitempty"`
	ResetAssignedTo     bool                `json:"reset_assigned_to,omitempty"`
	ResetQaContact      bool                `json:"reset_qa_contact,omitempty"`
	Resolution          string              `json:"resolution,omitempty"`
	Severity            string              `json:"severity,omitempty"`
	Status              string              `json:"status,omitempty"`
	Summary             string              `json:"summary,omitempty"`
	TargetMilestone     string              `json:"target_milestone,omitempty"`
	Url                 string              `json:"url,omitempty"`
	Version             string              `json:"version,omitempty"`
	Whiteboard          string              `json:"whiteboard,omitempty"`
	WorkTime            int64               `json:"work_time,omitempty"`
}

func (u *Update) Resource() string {
	return fmt.Sprintf("/bug/%d", u.Id)
}

type Comment struct {
	Body       string   `json:"body,omitempty"`
	IsPrivate  []string `json:"is_private,omitempty"`
	IsMarkdown []string `json:"is_markdown,omitempty"`
}

type UpdateFlag struct {
	Name      string `json:"name,omitempty"`
	TypeId    int    `json:"type_id,omitempty"`
	Status    string `json:"status"` // required
	Requestee string `json:"Requestee,omitempty"`
	Id        int    `json:"id,omitempty"`
	New       bool   `json:"new,omitempty"`
}

type AddRemoveSetInt struct {
	Add    []int `json:"add,omitempty"`
	Remove []int `json:"remove,omitempty"`
	Set    []int `json:"set,omitempty"`
}

type AddRemoveSetString struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
	Set    []string `json:"set,omitempty"`
}

type AddRemoveString struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

type UpdateResponse struct {
	Bugs []BugUpdate `json:"bugs"`
}

type BugUpdate struct {
	Id             int               `json:"id"`
	Alias          []string          `json:"alias"`
	LastChangeTime string            `json:"last_change_time"`
	Changes        map[string]Change `json:"changes"`
}

type Change struct {
	Added   string `json:"added"`
	Removed string `json:"removed"`
}
