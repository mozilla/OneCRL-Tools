package api

import "net/http"

// An Expecter returns the HTTP status code that signifies an successful response.
//
// It is intended that consumers of this API embed the provided types in
// a declarative fashion. For example:
//
//	type GetBug struct {
//		...
//		api.Ok
//  }
type Expecter interface {
	Expect() int
}

type Ok struct{}
type Created struct{}

func (ok *Ok) Expect() int     { return http.StatusOK }
func (c *Created) Expect() int { return http.StatusCreated }
