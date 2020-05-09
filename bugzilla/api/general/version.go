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
