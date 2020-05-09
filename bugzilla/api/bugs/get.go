package bugs

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api"
)

// https://bugzilla.readthedocs.io/en/latest/api/core/v1/bug.html#get-bug
type Get struct {
	Id int
	api.Get
	api.Ok
}

func (g *Get) Resource() string {
	return fmt.Sprintf("/bug/%d", g.Id)
}

type Search struct {
	Ids []int
	api.Get
	api.Ok
}

func (s *Search) AddBug(bug int) *Search {
	if s.Ids == nil {
		s.Ids = []int{bug}
	} else {
		s.Ids = append(s.Ids, bug)
	}
	return s
}

func (s *Search) AddBugs(bugs ...int) *Search {
	if s.Ids == nil {
		s.Ids = bugs
	} else {
		s.Ids = append(s.Ids, bugs...)
	}
	return s
}

func (s *Search) Resource() string {
	// Encodes the search query as described by the following doc...
	//
	// You can also use Search Bugs to return more than one bug at a time by specifying bug IDs as the search terms.
	//
	// GET /rest/bug?id=12434,43421
	if s.Ids == nil {
		s.Ids = []int{}
	}
	ids := make([]string, len(s.Ids))
	for i, id := range s.Ids {
		ids[i] = strconv.Itoa(id)
	}
	return fmt.Sprintf("/bug?id=%s", strings.Join(ids, ","))
}

type GetResponse struct {
	Faults []string `json:"faults"`
	Bugs   []Bug    `json:"bugs"`
}

type Bug struct {
	ActualTime          int64       `json:"actual_time"`
	Alias               []string    `json:"alias"`
	AssignedTo          string      `json:"assignedTo"`
	AssignedToDetail    User        `json:"assigned_to_detail"`
	Blocks              []int       `json:"blocks"`
	CC                  []string    `json:"cc"`
	CcDetail            []User      `json:"cc_detail"`
	Classification      string      `json:"classification"`
	Component           string      `json:"component"`
	CreationTime        string      `json:"creation_time"`
	Creator             string      `json:"creator"`
	CreatorDetail       User        `json:"creator_detail"`
	Deadline            string      `json:"deadline"`
	DependsOn           []int       `json:"depends_on"`
	DupeOf              int         `json:"dupe_of"`
	EstimatedTime       int64       `json:"estimated_time"`
	Flags               []GetFlag   `json:"flags"`
	Groups              []string    `json:"groups"`
	ID                  int         `json:"id"`
	IsCcAccessible      bool        `json:"is_cc_accessible"`
	IsConfirmed         bool        `json:"is_confirmed"`
	IsOpen              bool        `json:"is_open"`
	IsCreatorAccessible bool        `json:"is_creator_accessible"`
	Keywords            []string    `json:"keywords"`
	LastChangeTime      string      `json:"last_change_time"`
	OpSys               string      `json:"op_sys"`
	Platform            string      `json:"platform"`
	Priority            string      `json:"priority"`
	Product             string      `json:"product"`
	QaContact           string      `json:"qa_contact"`
	QaContactDetail     interface{} `json:"qa_contact_detail"`
	RemainingTime       int64       `json:"remaining_time"`
	Resolution          string      `json:"resolution"`
	SeeAlso             []string    `json:"see_also"`
	Severity            string      `json:"severity"`
	Status              string      `json:"status"`
	Summary             string      `json:"summary"`
	TargetMilestone     string      `json:"target_milestone"`
	UpdateToken         string      `json:"update_token"`
	URL                 string      `json:"url"`
	Version             string      `json:"version"`
	Whiteboard          string      `json:"whiteboard"`
}

type User struct {
	Id       int    `json:"id,omitempty"`
	RealName string `json:"real_name,omitempty"`
	Name     string `json:"name,omitempty"`
}

type GetFlag struct {
	Id               int    `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	TypeId           int    `json:"type_id,omitempty"`
	CreationDate     string `json:"creation_date,omitempty"`
	ModificationDate string `json:"modification_date,omitempty"`
	Status           string `json:"status,omitempty"`
	Setter           string `json:"setter,omitempty"`
	Requestee        string `json:"requestee,omitempty"`
}
