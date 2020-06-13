/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package api

// Every Record in Kinto has attached to it an ID and last-modified data.
// The best way to use this struct is to embed a pointer to it within
// your own schema.
//
//     type LegoSet struct {
//         branding string
//         legos    []Lego
//         *api.Record
//     }
//
// This enables you to leave the Kinto metadata out in your in code while
// receiving it in full from Kinto when using your struct as a serde target.
//
//     starWars := NewLegoSet(...)
//     fmt.Println(starWars.Record)
//     client.NewRecord(&starWars)
//     fmt.Println(starWars.Record.LastModified)
//
// For more details see https://docs.kinto-storage.org/en/stable/api/1.x/records.html
type Record struct {
	Id           string `json:"id,omitempty"`
	LastModified uint64 `json:"last_modified,omitempty"`
}

func (r *Record) ID() string {
	return r.Id
}

type Recorded interface {
	ID() string
}

type DeleteResponse struct {
	Data struct {
		Deleted      bool   `json:"deleted"`
		Id           string `json:"id"`
		LastModified int64  `json:"last_modified"`
	} `json:"data"`
}
