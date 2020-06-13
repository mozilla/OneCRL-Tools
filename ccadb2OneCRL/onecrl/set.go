/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package onecrl

import (
	"fmt"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/common"
	log "github.com/sirupsen/logrus"
)

// A Set is a facade that splits OneCRL into two maps - one for lookups
// into the entries that are identified by the issuer:serial combination, and one
// for lookups into the entries that are identified by the subject:keyhash combination.
//
// Asking if a CCADB entry is within this type is effectively asking whether it is in
// at least of the aforementioned maps.
type Set struct {
	*common.SetImpl
}

func NewSetFrom(records *OneCRL) *Set {
	s := NewSet()
	if records == nil {
		return s
	}
	for _, record := range records.Data {
		s.Add(record)
	}
	return s
}

func NewSet() *Set {
	return &Set{SetImpl: common.NewSetImpl(func() common.Set {
		return NewSet()
	})}
}

func (s *Set) Add(record common.Record) {
	_, ok := record.(*Record)
	if !ok {
		log.WithField("record", record).
			WithField("type", fmt.Sprintf("%T", record)).
			Panic("attempted to add a non-OneCRL record type to a onecrl.Set")
	}
	s.SetImpl.Add(record)
}

func (s *Set) Get(record common.Record) *Record {
	r := s.SetImpl.Get(record)
	if r == nil {
		return nil
	}
	return r.(*Record)
}
