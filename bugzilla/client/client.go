/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/general"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/attachments"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/auth"
	"github.com/mozilla/OneCRL-Tools/bugzilla/api/bugs"
)

type Client struct {
	base          string
	authenticator auth.Authenticator
	inner         *http.Client
	tool          string
}

// NewClient constructs an unauthenticated client. To add
// and authenticator please see the WithAuth method.
//
// The provided "host" string must be <protocol>://<hostname>[:<port>]
// WITHOUT any path. The "rest" resource is automatically appended to
// every constructed client.
func NewClient(host string) *Client {
	return &Client{
		base:          host + "/rest",
		authenticator: new(auth.Unauthenticated),
		inner:         new(http.Client),
		tool:          "https://github.com/mozilla/OneCRL-Tools/bugzilla",
	}
}

func (c *Client) WithAuth(authenticator auth.Authenticator) *Client {
	c.authenticator = authenticator
	return c
}

// WithToolHeader sets the header value for X-AUTOMATED-TOOL, which
// is sent with every request.
//
// By default, this is set to "https://github.com/mozilla/OneCRL-Tools/bugzilla",
// however it would be appreciated if consumers of this library set this to
// pointer to the code that is actually making API calls.
func (c *Client) WithToolHeader(tool string) *Client {
	c.tool = tool
	return c
}

func (c *Client) Version() (*general.VersionResponse, error) {
	resp := new(general.VersionResponse)
	return resp, c.do(new(general.Version), resp)
}

func (c *Client) CreateBug(bug *bugs.Create) (*bugs.CreateResponse, error) {
	resp := new(bugs.CreateResponse)
	return resp, c.do(bug, resp)
}

func (c *Client) GetBug(bug int) (*bugs.GetResponse, error) {
	resp := new(bugs.GetResponse)
	return resp, c.do(&bugs.Get{Id: bug}, resp)
}

func (c *Client) CreateAttachment(attachment *attachments.Create) (*attachments.CreateResponse, error) {
	resp := new(attachments.CreateResponse)
	return resp, c.do(attachment, resp)
}

func (c *Client) UpdateBug(bug *bugs.Update) (*bugs.UpdateResponse, error) {
	resp := new(bugs.UpdateResponse)
	return resp, c.do(bug, resp)
}

func (c *Client) do(in api.Endpoint, out interface{}) error {
	req, err := c.newRequest(in)
	if err != nil {
		return err
	}
	resp, err := c.inner.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != in.Expect() {
		return errors.New(string(b))
	}
	return json.Unmarshal(b, out)
}

func (c *Client) newRequest(endpoint api.Endpoint) (*http.Request, error) {
	req, err := http.NewRequest(endpoint.Method(), c.base+endpoint.Resource(), nil)
	if err != nil {
		return nil, err
	}
	if endpoint.Method() != http.MethodGet {
		b, err := json.Marshal(endpoint)
		if err != nil {
			return nil, err
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(b))
	}
	req.Header.Set("X-AUTOMATED-TOOL", c.tool)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.authenticator.Authenticate(req.Header)
	return req, nil
}
