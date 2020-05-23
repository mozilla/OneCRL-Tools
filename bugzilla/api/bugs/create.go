/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package bugs

import (
	"github.com/mozilla/OneCRL-Tools/bugzilla/api"
)

// https://bugzilla.readthedocs.io/en/latest/api/core/v1/bug.html#create-bug
type Create struct {
	Product          string   `json:"product"`
	Component        string   `json:"component"`
	Summary          string   `json:"summary"`
	Version          string   `json:"version"`
	Description      string   `json:"description,omitempty"`
	OpSys            string   `json:"op_sys,omitempty"`
	Platform         string   `json:"platform,omitempty"`
	Priority         string   `json:"priority,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Alias            []string `json:"alias,omitempty"`
	AssignedTo       string   `json:"assigned_to,omitempty"`
	Cc               []string `json:"cc,omitempty"`
	CommentIsPrivate bool     `json:"comment_is_private,omitempty"`
	CommentTags      []string `json:"comment_tags,omitempty"`
	IsMarkdown       bool     `json:"is_markdown,omitempty"`
	Groups           []string `json:"groups,omitempty"`
	Keywords         []string `json:"keywords,omitempty"`
	QaContact        string   `json:"qa_contact,omitempty"`
	Status           string   `json:"status,omitempty"`
	Resolution       string   `json:"resolution,omitempty"`
	TargetMilestone  string   `json:"target_milestone,omitempty"`
	Type             string   `json:"type,omitempty"`
	Flags            []Flag   `json:"flags,omitempty"`
	api.Post
	api.Ok
}

func (c *Create) Resource() string {
	return "/bug"
}

type Flag struct {
	Name      string `json:"name,omitempty"`
	TypeId    int    `json:"type_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Requestee string `json:"requestee,omitempty"`
}

type CreateResponse struct {
	Id int `json:"id"`
}
