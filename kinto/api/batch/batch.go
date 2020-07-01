/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package batch

import (
	"math"

	"github.com/mozilla/OneCRL-Tools/kinto/api"
	"github.com/mozilla/OneCRL-Tools/kinto/api/authz"
)

// https://docs.kinto-storage.org/en/stable/api/1.x/batch.html
type Batch struct {
	Defaults *Defaults        `json:"defaults"`
	Requests []BatchedRequest `json:"requests"`
}

type BatchedRequest struct {
	Body *api.Payload `json:"body"`
}

type Defaults struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func (b *Batch) Post() string {
	return "/batch"
}

// NewBatch returns a Batch whose inner requests are homogenous (Kinto allows for mixing requests
// within batch operations (say, for example, two POSTs of records and one GET of a collection)) however this
// API does not.
func NewBatch(records []interface{}, perms *authz.Permissions, method, path string) *Batch {
	requests := make([]BatchedRequest, len(records))
	for i, record := range records {
		requests[i] = BatchedRequest{Body: api.NewPayload(record, perms)}
	}
	return &Batch{Defaults: &Defaults{
		Method: method,
		Path:   path,
	}, Requests: requests}
}

// NewBatches returns a slice of Batch whose inner requests are homogenous (Kinto allows for mixing requests
// within batch operations (say, for example, two POSTs of records and one GET of a collection)) however this
// API does not.
//
// maxRequest must be less-than-or equal to Kinto's configured "batch_max_requests". See Client.BatchMaxRequests for
// more information on how to retrieve this value programatically.
func NewBatches(records []interface{}, maxRequests int, perms *authz.Permissions, method, path string) []*Batch {
	batches := make([]*Batch, numBatches(len(records), maxRequests))
	for i := 0; i < len(batches); i++ {
		start := i * maxRequests
		end := min(start+maxRequests, len(records))
		batches[i] = NewBatch(records[start:end], perms, method, path)
	}
	return batches
}

func numBatches(records, maxRequests int) int {
	return int(math.Ceil(float64(records) / float64(maxRequests)))
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}
