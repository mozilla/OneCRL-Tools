package attachments

import (
	"fmt"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api"
)

// https://bugzilla.readthedocs.io/en/latest/api/core/v1/attachment.html#create-attachment
type Create struct {
	BugId       int    `json:"-"`
	Ids         []int  `json:"ids"`
	Data        []byte `json:"data"`
	FileName    string `json:"file_name"`
	Summary     string `json:"summary"`
	ContentType string `json:"content_type"`
	Comment     string `json:"comment,omitempty"`
	IsPatch     bool   `json:"is_patch,omitempty"`
	IsPrivate   bool   `json:"is_private,omitempty"`
	IsMarkdown  bool   `json:"is_markdown,omitempty"`
	Flags       []Flag `json:"flags,omitempty"`
	api.Post
	api.Created
}

func (c *Create) Resource() string {
	return fmt.Sprintf("/bug/%d/attachment", c.BugId)
}

func (c *Create) AddBug(bug int) *Create {
	if c.Ids == nil {
		c.Ids = []int{bug}
	} else {
		c.Ids = append(c.Ids, bug)
	}
	return c
}

func (c *Create) AddBugs(bugs ...int) *Create {
	if c.Ids == nil {
		c.Ids = bugs
	} else {
		c.Ids = append(c.Ids, bugs...)
	}
	return c
}

type CreateResponse struct {
	Ids []int `json:"ids"`
}
