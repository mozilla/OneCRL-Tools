/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package buckets

import (
	"fmt"
)

// https://docs.kinto-storage.org/en/stable/api/1.x/buckets.html
type Bucket struct {
	ID string `json:"id"`
}

func NewBucket(name string) *Bucket {
	return &Bucket{ID: name}
}

func (b *Bucket) Get() string {
	return fmt.Sprintf("/buckets/%s", b.ID)
}

func (b *Bucket) Post() string {
	return "/buckets"
}

func (b *Bucket) Patch() string {
	return b.Get()
}

func (b *Bucket) Put() string {
	return b.Get()
}
