/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package kinto // import "github.com/mozilla/OneCRL-Tools/kinto"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/mozilla/OneCRL-Tools/kinto/api"
	"github.com/mozilla/OneCRL-Tools/kinto/api/auth"
	"github.com/mozilla/OneCRL-Tools/kinto/api/authz"
	"github.com/mozilla/OneCRL-Tools/kinto/api/batch"
	"github.com/mozilla/OneCRL-Tools/kinto/api/buckets"
	"github.com/mozilla/OneCRL-Tools/kinto/plugins/kintosigner"
)

type expectations map[int]bool

var (
	ok          = expectations{http.StatusOK: true}
	okOrCreated = expectations{http.StatusOK: true, http.StatusCreated: true}
)

// Client is a thread safe client for the Kinto REST API.
//
// For information on the API that this client targets,
// please see the Kinto 1.x API documentation:
//
// https://docs.kinto-storage.org/en/stable/api/
type Client struct {
	host          string
	base          string
	scheme        string
	tool          string
	backoff       time.Duration
	authenticator auth.Authenticator
	inner         *http.Client
	lock          sync.Mutex
}

// NewClient constructs a client with the scheme (E.G "https"),
// the host (E.G "settings.stage.mozaws.net"), and the API base (E.G "/v1").
func NewClient(scheme, host, base string) *Client {
	return &Client{
		host:          host,
		base:          base,
		scheme:        scheme,
		inner:         new(http.Client),
		authenticator: new(auth.Unauthenticated),
		tool:          "https://github.com/mozilla/OneCRL-Tools/kinto",
		lock:          sync.Mutex{},
	}
}

// WithAuthenticator sets the authentication backend for future requests. The use of this
// configuration lazy and done on a per-request basis, so it is possible to use the same
// client but swap accounts in-and-out as necessary.
//
// Although this API is thread safe it is not advised to swap out authentication methods
// for client that is shared between goroutines as other threads may be assuming that a
// given authenticator is being  used, which can lead to surprising results.
func (c *Client) WithAuthenticator(authenticator auth.Authenticator) *Client {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.authenticator = authenticator
	return c
}

// WithToolHeader sets the header value for X-AUTOMATED-TOOL, which
// is sent with every request.
//
// By default, this is set to "https://github.com/mozilla/OneCRL-Tools/kinto",
// however it would be appreciated if consumers of this library set this to
// pointer to the code that is actually making API calls.
func (c *Client) WithToolHeader(tool string) *Client {
	c.tool = tool
	return c
}

// Alive returns back whether any error occurred while doing a GET on /
func (c *Client) Alive() bool {
	req, err := c.newRequest(http.MethodGet, "/", nil)
	if err != nil {
		panic(err)
	}
	return c.do(req, nil, nil) == nil
}

// NewAdmin is the same as NewAccount, however with the "admin" user pre-configured.
func (c *Client) NewAdmin(password string) error {
	return c.NewAccount(&auth.User{
		Username: "admin",
		Password: password,
	})
}

// NewAccount creates a new Kinto local account using the provide principal and password.
//
// See https://docs.kinto-storage.org/en/stable/api/1.x/accounts.html#put--accounts-(user_id) for details.
func (c *Client) NewAccount(user *auth.User) error {
	payload := api.NewPayload(user, nil)
	req, err := c.newRequest(http.MethodPut, user.Put(), &payload)
	if err != nil {
		return err
	}
	return c.do(req, &payload, okOrCreated)
}

// NewBucket creates a new bucket with default permissions.
//
// See https://docs.kinto-storage.org/en/stable/api/1.x/buckets.html#post--buckets for details.
func (c *Client) NewBucket(bucket *buckets.Bucket) error {
	return c.NewBucketWithPermissions(bucket, nil)
}

// NewBucketWithPermissions creates a new bucket with the provided permissions.
//
// See https://docs.kinto-storage.org/en/stable/api/1.x/buckets.html#post--buckets for details.
func (c *Client) NewBucketWithPermissions(bucket *buckets.Bucket, perms *authz.Permissions) error {
	payload := api.NewPayload(bucket, perms)
	req, err := c.newRequest(http.MethodPost, bucket.Post(), &payload)
	if err != nil {
		return err
	}
	return c.do(req, &payload, okOrCreated)
}

// NewCollection creates a new collection with the provided permissions.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/collections.html#post--buckets-(bucket_id)-collections
func (c *Client) NewCollection(collection api.Poster) error {
	return c.NewCollectionWithPermissions(collection, nil)
}

// NewCollectionWithPermissions creates a new collection with the provided permissions.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/collections.html#post--buckets-(bucket_id)-collections
func (c *Client) NewCollectionWithPermissions(collection api.Poster, perms *authz.Permissions) error {
	payload := api.NewPayload(collection, perms)
	req, err := c.newRequest(http.MethodPost, collection.Post(), &payload)
	if err != nil {
		return err
	}
	return c.do(req, &payload, okOrCreated)
}

// Batch POSTs a single batch request. Note that the size of a batch request is bounded
// by the remote server's "batch_max_requests" settings (which can be found under "settings" under the root resource).
//
// The most reliable way to to use this endpoint is to query this limit via `BatchMaxRequests` and use that value
// in the batch.NewBatches API.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/batch.html
func (c *Client) Batch(b *batch.Batch) error {
	req, err := c.newRequest(http.MethodPost, b.Post(), &b)
	if err != nil {
		return err
	}
	return c.do(req, nil, okOrCreated)
}

// AllRecords retrieves all records for the given collection.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/records.html#retrieving-stored-records
func (c *Client) AllRecords(collection api.Getter) error {
	r, err := c.newRequest(http.MethodGet, collection.Get(), nil)
	if err != nil {
		return err
	}
	return c.do(r, collection, ok)
}

// NewRecord POSTs a new record under the given collection with default permissions.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/records.html#uploading-a-record
func (c *Client) NewRecord(collection api.Getter, record interface{}) error {
	return c.NewRecordWithPermissions(collection, record, nil)
}

// NewRecordWithPermissions POSTs a new record under the given collection with the given permissions.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/records.html#uploading-a-record
func (c *Client) NewRecordWithPermissions(collection api.Getter, record interface{}, perms *authz.Permissions) error {
	payload := api.NewPayload(record, perms)
	req, err := c.newRequest(http.MethodPost, collection.Get(), &payload)
	if err != nil {
		return err
	}
	return c.do(req, &payload, okOrCreated)
}

// UpdateRecord PATCHes a given record under the given collection with default permissions.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/records.html#patch--buckets-(bucket_id)-collections-(collection_id)-records-(record_id)
func (c *Client) UpdateRecord(collection api.Getter, record api.Recorded) error {
	return c.UpdateRecordWithPermissions(collection, record, nil)
}

// UpdateRecordWithPermissions PATCHes a given record under the given collection with the given permissions.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/records.html#patch--buckets-(bucket_id)-collections-(collection_id)-records-(record_id)
func (c *Client) UpdateRecordWithPermissions(collection api.Getter, record api.Recorded, perms *authz.Permissions) error {
	payload := api.NewPayload(record.(interface{}), perms)
	req, err := c.newRequest(http.MethodPatch, collection.Get()+"/"+record.ID(), &payload)
	if err != nil {
		return err
	}
	return c.do(req, &payload, okOrCreated)
}

// ToReview puts the given collection into the "to-review" state.
//
// For details on the Kinto Signer plugin, please see:
// https://github.com/Kinto/kinto-signer
func (c *Client) ToReview(collection api.Patcher) error {
	req, err := c.newRequest(http.MethodPatch, collection.Patch(), kintosigner.ToReview())
	if err != nil {
		return err
	}
	return c.do(req, nil, okOrCreated)
}

// ToWIP puts the given collection into the "work-in-progress" state.
//
// For details on the Kinto Signer plugin, please see:
// https://github.com/Kinto/kinto-signer
func (c *Client) ToWIP(collection api.Patcher) error {
	req, err := c.newRequest(http.MethodPatch, collection.Patch(), kintosigner.WIP())
	if err != nil {
		return err
	}
	return c.do(req, nil, okOrCreated)
}

// ToSign puts the given collection into the "to-sign" state.
//
// For details on the Kinto Signer plugin, please see:
// https://github.com/Kinto/kinto-signer
func (c *Client) ToSign(collection api.Patcher) error {
	req, err := c.newRequest(http.MethodPatch, collection.Patch(), kintosigner.ToSign())
	if err != nil {
		return err
	}
	return c.do(req, nil, okOrCreated)
}

// ToSigned puts the given collection into the "signed" state.
//
// For details on the Kinto Signer plugin, please see:
// https://github.com/Kinto/kinto-signer
func (c *Client) ToSigned(collection api.Patcher) error {
	req, err := c.newRequest(http.MethodPatch, collection.Patch(), kintosigner.Signed())
	if err != nil {
		return err
	}
	return c.do(req, nil, okOrCreated)
}

// ToRollBack puts the given collection into the "to-rollback" state.
//
// For details on the Kinto Signer plugin, please see:
// https://github.com/Kinto/kinto-signer
func (c *Client) ToRollBack(collection api.Patcher) error {
	req, err := c.newRequest(http.MethodPatch, collection.Patch(), kintosigner.ToRollback())
	if err != nil {
		return err
	}
	return c.do(req, nil, okOrCreated)
}

// ToResign puts the given collection into the "to-resign" state.
//
// For details on the Kinto Signer plugin, please see:
// https://github.com/Kinto/kinto-signer
func (c *Client) ToResign(collection api.Patcher) error {
	req, err := c.newRequest(http.MethodPatch, collection.Patch(), kintosigner.ToResign())
	if err != nil {
		return err
	}
	return c.do(req, nil, okOrCreated)
}

// TryAuth does a GET on the Kinto's root resource and checks for the presence of user
// metadata in order to determine the configured authenticator successfully authenticates.
//
// See https://docs.kinto-storage.org/en/stable/api/1.x/authentication.html#try-authentication for details.
func (c *Client) TryAuth() (bool, error) {
	r, err := c.newRequest(http.MethodGet, "/", nil)
	if err != nil {
		return false, err
	}
	ret := make(map[string]interface{})
	err = c.do(r, &ret, map[int]bool{200: true})
	if err != nil {
		return false, err
	}
	_, authenticated := ret["user"]
	return authenticated, nil
}

// BatchMaxRequests retrieves the "settings.batch_max_requests" from the utility endpoint.
//
// This API is most useful when used in conjunction withe batch.NewBatches API.
//
// For details, please see:
// https://docs.kinto-storage.org/en/stable/api/1.x/utilities.html#api-utilities
func (c *Client) BatchMaxRequests() (int, error) {
	answer := struct {
		Settings struct {
			BatchMaxRequests int `json:"batch_max_requests"`
		} `json:"settings"`
	}{}
	r, err := c.newRequest(http.MethodGet, "/", nil)
	if err != nil {
		return 0, err
	}
	err = c.do(r, &answer, map[int]bool{200: true})
	if err != nil {
		return 0, err
	}
	return answer.Settings.BatchMaxRequests, nil
}

func (c *Client) newRequest(method string, endpoint string, body interface{}) (*http.Request, error) {
	var b io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		b = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("%s://%s%s%s", c.scheme, c.host, c.base, endpoint), b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-AUTOMATED-TOOL", c.tool)
	return req, nil
}

func (c *Client) do(r *http.Request, target interface{}, accept expectations) error {
	backoff := c.getBackoff()
	c.authenticate(r)
	if backoff > 0 {
		// Kinto kindly asks us that we backoff when necessary
		// See https://docs.kinto-storage.org/en/stable/api/1.x/backoff.html
		log.Printf("Kinto has asked us to backoff for %d seconds\n", c.backoff)
		time.Sleep(time.Second * c.backoff)
	}
	resp, err := c.inner.Do(r)
	if err != nil {
		return err
	}
	receivedBackoff := resp.Header.Get("Backoff")
	if receivedBackoff != "" {
		b, err := strconv.Atoi(receivedBackoff)
		if err != nil {
			return fmt.Errorf(
				"Kinto gave us a Backoff header, but "+
					"it did not parse to an integer. Got '%s'",
				receivedBackoff)
		}
		c.setBackoff(time.Second * time.Duration(b))
	} else {
		c.setBackoff(time.Duration(0))
	}
	if accept != nil {
		if _, ok := accept[resp.StatusCode]; !ok {
			defer resp.Body.Close()
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("expected status code %v, got %d", accept, resp.StatusCode)
			}
			return fmt.Errorf("expected status code %v, got %d. Message %s", accept, resp.StatusCode, string(b))
		}
	}
	if target != nil {
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(&target)
	}
	return nil
}

func (c *Client) authenticate(r *http.Request) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.authenticator.Authenticate(r)
}

func (c *Client) getBackoff() time.Duration {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.backoff
}

func (c *Client) setBackoff(backoff time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.backoff = backoff
}
