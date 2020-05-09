package attachments

import (
	"fmt"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api"
)

// https://bugzilla.readthedocs.io/en/latest/api/core/v1/attachment.html#get-attachment
type AllAttachments struct {
	BugID int
	api.Ok
	api.Get
}

func (a *AllAttachments) Resource() string {
	return fmt.Sprintf("/bug/%d/attachment", a.BugID)
}

type SpecificAttachment struct {
	AttachmentID int
	api.Ok
	api.Get
}

func (s *SpecificAttachment) Resource() string {
	return fmt.Sprintf("/bug/attachment/%d", s.AttachmentID)
}

type GetResponse struct {
	Data           string `json:"data"`
	Size           int    `json:"size"`
	CreationTime   string `json:"creation_time"`
	LastChangeTime string `json:"last_change_time"`
	Id             int    `json:"id"`
	BugId          int    `json:"bug_id"`
	FileName       string `json:"file_name"`
	Summary        string `json:"summary"`
	ContentType    string `json:"content_type"`
	IsPrivate      bool   `json:"is_private"`
	IsObsolete     bool   `json:"is_obsolete"`
	IsPatch        bool   `json:"is_patch"`
	Creator        string `json:"creator"`
	Flags          []Flag `json:"flags"`
}

type Flag struct {
	Id                int    `json:"id"`
	Name              string `json:"name"`
	TypeId            int    `json:"type_id"`
	CreationDate      string `json:"creation_date"`
	Modification_date string `json:"modification_date"`
	Status            string `json:"status"`
	Setter            string `json:"setter"`
	Requestee         string `json:"requestee"`
}
