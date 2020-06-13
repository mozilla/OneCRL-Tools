/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"fmt"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/common"
	log "github.com/sirupsen/logrus"
)

type Set struct {
	*common.SetImpl
}

func NewSetFrom(records CCADB) *Set {
	s := NewSet()
	if records == nil {
		return s
	}
	for _, record := range records {
		if OneCRLStatus(record.OneCRLStatus) == ReadyToAdd {
			s.Add(record)
		}
	}
	return s
}

func NewSet() *Set {
	return &Set{SetImpl: common.NewSetImpl(func() common.Set { return NewSet() })}
}

func (s *Set) Add(record common.Record) {
	_, ok := record.(*Certificate)
	if !ok {
		log.WithField("record", record).
			WithField("type", fmt.Sprintf("%T", record)).
			Panic("attempted to add a non-CCADB record type to a ccadb.Set")
	}
	s.SetImpl.Add(record)
}
