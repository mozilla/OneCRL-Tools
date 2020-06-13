/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package collections

import (
	"fmt"

	"github.com/mozilla/OneCRL-Tools/kinto/api/buckets"
)

// https://docs.kinto-storage.org/en/stable/api/1.x/collections.html
type Collection struct {
	ID     string          `json:"id"`
	Bucket *buckets.Bucket `json:"-"`
}

func NewCollection(bucket *buckets.Bucket, name string) *Collection {
	return &Collection{ID: name, Bucket: bucket}
}

func (c *Collection) Get() string {
	return fmt.Sprintf("%s/records", c.Patch())
}

func (c *Collection) Post() string {
	return fmt.Sprintf("%s/collections", c.Bucket.Get())
}

func (c *Collection) Patch() string {
	return fmt.Sprintf("%s/collections/%s", c.Bucket.Get(), c.ID)
}

func (c *Collection) Put() string {
	return c.Patch()
}
