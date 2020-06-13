/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package common

import (
	"reflect"

	log "github.com/sirupsen/logrus"
)

type Record interface {
	IssuerSerial() *IssuerSerial
	SubjectKeyHash() *SubjectKeyHash
	Type() Type
}

type Set interface {
	Add(record Record)
	Contains(record Record) bool
	Iter() <-chan Record
	Union(other Set) Set
	Difference(other Set) Set
	Intersection(other Set) Set
}

type Type int

const (
	IssuerSerialType Type = iota
	SubjectKeyHashType
	Either
)

func (t *Type) String() string {
	switch *t {
	case IssuerSerialType:
		return "IssuerSerial"
	case SubjectKeyHashType:
		return "SubjectKeyHash"
	case Either:
		return "Either"
	}
	log.Panic()
	return ""
}

// SetImpl holds a mapping of IssuerSerial -> Record and a mapping SubjectKeyHash -> Record
// and provides a logical, singular, view into both datasets.
//
// For example, if you wish to find if a Record is within a SetImpl then the provided record
// will be asked for its type. If it is an IssuerSerialType then the issuerSerial map will be
// checked. If it is a SubjectKeyHashType, then the subjectKeyHash map will be checked. If it
// is Either then both will be checked.
//
// Consumers of this struct SHOULD embed a *SetImpl and override the Add method if they wish to make
// the underlying Records homogenous.
//
// SetImpl has a dependency injection requirement on a factory function for a specific type of Set.
// This is required as the set operations (Union, Difference, and Intersection) need to return a new
// Set
type SetImpl struct {
	setFactory     func() Set
	issuerSerial   map[IssuerSerial]Record
	subjectKeyHash map[SubjectKeyHash]Record
}

func NewSetImpl(setFactory func() Set) *SetImpl {
	return &SetImpl{
		setFactory:     setFactory,
		issuerSerial:   make(map[IssuerSerial]Record),
		subjectKeyHash: make(map[SubjectKeyHash]Record),
	}
}

func NewDynamicSetImpl() *SetImpl {
	return NewSetImpl(func() Set {
		return NewDynamicSetImpl()
	})
}

// Add will ATTEMPT to add the provided to record to the set.
// If the record cannot serialize itself into the appropriate type
// (IsserSerial:SubjectKeyHash) then it will be silent ignored.
// Implementors of Record SHOULD log errors this case as implementors
// are much closer to the data and can provide more meaningful messages
// than can be accomplished in this stack frame.
//
// The reason why this is an attemp is because there are entries within
// staging that are junk data  that result in a B64 or ASN1 decoding error.
// We would HOPE that "real" entries aren't going to suffer from
// this, however we have not way to tell which entries are
// test data and which are destined for production. I
// suppose if an entry doesn't show up on Bugzilla, but you
// see it logged, then we know why.
func (s *SetImpl) Add(record Record) {
	switch record.Type() {
	case IssuerSerialType:
		is := record.IssuerSerial()
		if is == nil {
			return
		}
		s.issuerSerial[*is] = record
	case SubjectKeyHashType:
		skh := record.SubjectKeyHash()
		if skh == nil {
			return
		}
		s.subjectKeyHash[*skh] = record
	case Either:
		is := record.IssuerSerial()
		if is == nil {
			return
		}
		skh := record.SubjectKeyHash()
		if skh == nil {
			return
		}
		s.issuerSerial[*is] = record
		s.subjectKeyHash[*skh] = record
	default:
		log.WithField("record", record).
			WithField("type", record.Type()).
			Panic("unknown record type")
	}
}

func (s *SetImpl) Get(record Record) Record {
	switch record.Type() {
	case IssuerSerialType:
		is := record.IssuerSerial()
		if is == nil {
			return nil
		}
		if v, ok := s.issuerSerial[*is]; ok {
			return v
		}
	case SubjectKeyHashType:
		skh := record.SubjectKeyHash()
		if skh == nil {
			return nil
		}
		if v, ok := s.subjectKeyHash[*skh]; ok {
			return v
		}
	case Either:
		is := record.IssuerSerial()
		if is != nil {
			if v, ok := s.issuerSerial[*is]; ok {
				return v
			}
		}
		skh := record.SubjectKeyHash()
		if is != nil {
			if v, ok := s.subjectKeyHash[*skh]; ok {
				return v
			}
		}
	}
	return nil
}

func (s *SetImpl) Iter() <-chan Record {
	// We have two backing maps that can both
	// hold a pointer to the same record, so
	// we need to "flatten" that view by
	// ensuring uniqueness via said pointer.
	m := make(map[uintptr]Record)
	for _, v := range s.subjectKeyHash {
		m[reflect.ValueOf(v).Pointer()] = v
	}
	for _, v := range s.issuerSerial {
		m[reflect.ValueOf(v).Pointer()] = v
	}
	ret := make(chan Record, len(m))
	defer close(ret)
	for _, v := range m {
		ret <- v
	}
	return ret
}

func (s *SetImpl) Contains(record Record) bool {
	return s.Get(record) != nil
}

// Union returns the unino of self and other. If self and other
// are homogenous and of same type, then the returned Set will
// also be homogenous of the same type. Otherwise the returned set
// will be heterogeneous.
//
// If the Set returned by the set factory injected into this struct
// enforces type checking then this method will likely panic in the
// heterogeneous case.
func (s *SetImpl) Union(other Set) Set {
	union := s.setFactory()
	for r := range s.Iter() {
		union.Add(r)
	}
	for r := range other.Iter() {
		union.Add(r)
	}
	return union
}

// Difference returns a Set of all Records that are in self
// but are NOT in other. If self is homogenous then the returned
// Set will be homogenous and off the same type as self.
func (s *SetImpl) Difference(other Set) Set {
	difference := s.setFactory()
	for r := range s.Iter() {
		if !other.Contains(r) {
			difference.Add(r)
		}
	}
	return difference
}

// Intersection returns a Set of all Records that are both in self
// AND in other. If self is homogenous then the returned
//// Set will be homogenous and off the same type as self.
func (s *SetImpl) Intersection(other Set) Set {
	intersection := s.setFactory()
	for r := range s.Iter() {
		if other.Contains(r) {
			intersection.Add(r)
		}
	}
	return intersection
}
