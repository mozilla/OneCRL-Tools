package api

import "net/http"

// A Methoder returns the HTTP method that the target endpoint is listening on.
//
// It is intended that consumers of this API embed the provided types in
// a declarative fashion. For example:
//
//	type UpdateBug struct {
//		...
//		api.Update
//  }
type Methoder interface {
	Method() string
}

type Get struct{}
type Post struct{}
type Put struct{}
type Patch struct{}
type Delete struct{}
type Options struct{}
type Trace struct{}
type Head struct{}
type Connect struct{}

func (g *Get) Method() string     { return http.MethodGet }
func (p *Post) Method() string    { return http.MethodPost }
func (p *Put) Method() string     { return http.MethodPut }
func (p *Patch) Method() string   { return http.MethodPatch }
func (d *Delete) Method() string  { return http.MethodDelete }
func (o *Options) Method() string { return http.MethodOptions }
func (t *Trace) Method() string   { return http.MethodTrace }
func (h *Head) Method() string    { return http.MethodHead }
func (c *Connect) Method() string { return http.MethodConnect }
