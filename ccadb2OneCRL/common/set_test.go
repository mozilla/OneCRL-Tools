/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package common

import (
	"testing"
)

type TestRecord struct {
	is  IssuerSerial
	skh SubjectKeyHash
}

func NewRecord(is, skh string) *TestRecord {
	return &TestRecord{
		is:  IssuerSerial(is),
		skh: SubjectKeyHash(skh),
	}
}

func (t *TestRecord) Key() string {
	return string(t.is) + string(t.skh)
}

func (t *TestRecord) Type() Type {
	if t.skh != "" && t.is != "" {
		return Either
	}
	if t.skh != "" {
		return SubjectKeyHashType
	}
	if t.is != "" {
		return IssuerSerialType
	}
	panic("")
}

func (t *TestRecord) IssuerSerial() *IssuerSerial {
	return &t.is
}

func (t *TestRecord) SubjectKeyHash() *SubjectKeyHash {
	return &t.skh
}

func TestSetImpl_Add(t *testing.T) {
	s := NewDynamicSetImpl()
	s.Add(NewRecord("hello", ""))
	if len(s.issuerSerial) != 1 {
		t.Fatal()
	}
	if len(s.subjectKeyHash) != 0 {
		t.Fatal()
	}
	if !s.Contains(NewRecord("hello", "")) {
		t.Fatal()
	}
}

func TestSetImpl_Add2(t *testing.T) {
	s := NewDynamicSetImpl()
	s.Add(NewRecord("", "hello"))
	if len(s.issuerSerial) != 0 {
		t.Fatal()
	}
	if len(s.subjectKeyHash) != 1 {
		t.Fatal()
	}
	if !s.Contains(NewRecord("", "hello")) {
		t.Fatal()
	}
}

func TestSetImpl_Add3(t *testing.T) {
	s := NewDynamicSetImpl()
	s.Add(NewRecord("hi", "hello"))
	if len(s.issuerSerial) != 1 {
		t.Fatal()
	}
	if len(s.subjectKeyHash) != 1 {
		t.Fatal()
	}
	if !s.Contains(NewRecord("hi", "hello")) {
		t.Fatal()
	}
}

func TestSetImpl_Add4(t *testing.T) {
	s := NewDynamicSetImpl()
	s.Add(NewRecord("", "hello"))
	s.Add(NewRecord("hello", ""))
	if len(s.issuerSerial) != 1 {
		t.Fatal()
	}
	if len(s.subjectKeyHash) != 1 {
		t.Fatal()
	}
	if !s.Contains(NewRecord("", "hello")) {
		t.Fatal()
	}
	if !s.Contains(NewRecord("hello", "")) {
		t.Fatal()
	}
}

func TestSetImpl_Contains(t *testing.T) {
	s := NewDynamicSetImpl()
	if s.Contains(NewRecord("hello", "")) {
		t.Fatal()
	}
	if s.Contains(NewRecord("", "hello")) {
		t.Fatal()
	}
	if s.Contains(NewRecord("hello", "hello")) {
		t.Fatal()
	}
}

func TestSetImpl_Contains1(t *testing.T) {
	s := NewDynamicSetImpl()
	s.Add(NewRecord("", "hello"))
	if s.Contains(NewRecord("hello", "")) {
		t.Fatal()
	}
	if !s.Contains(NewRecord("", "hello")) {
		t.Fatal()
	}
}

func TestSetImpl_Contains2(t *testing.T) {
	s := NewDynamicSetImpl()
	s.Add(NewRecord("hello", ""))
	if !s.Contains(NewRecord("hello", "")) {
		t.Fatal()
	}
	if s.Contains(NewRecord("", "hello")) {
		t.Fatal()
	}
}

func TestSetImpl_Iter(t *testing.T) {
	s := NewDynamicSetImpl()
	want := []*TestRecord{
		NewRecord("hello", ""),
		NewRecord("", "hello"),
		NewRecord("ni hao", "hola"),
	}
	for _, r := range want {
		s.Add(r)
	}
	got := make(map[string]bool)
	num := 0
	for r := range s.Iter() {
		num += 1
		got[r.(*TestRecord).Key()] = true
	}
	if num != 3 {
		t.Fatal(num)
	}
	for _, w := range want {
		if _, ok := got[w.Key()]; !ok {
			t.Fatal()
		}
	}
}

func TestSetImpl_Union(t *testing.T) {
	a := NewDynamicSetImpl()
	b := NewDynamicSetImpl()
	a.Add(NewRecord("hello", ""))
	a.Add(NewRecord("", "hello"))
	b.Add(NewRecord("hi", ""))
	b.Add(NewRecord("", "hi"))
	b.Add(NewRecord("ni hao", "ni hao"))
	union := a.Union(b).(*SetImpl)
	if !union.Contains(NewRecord("hello", "")) {
		t.Fatal()
	}
	if !union.Contains(NewRecord("", "hello")) {
		t.Fatal()
	}
	if !union.Contains(NewRecord("hi", "")) {
		t.Fatal()
	}
	if !union.Contains(NewRecord("", "hi")) {
		t.Fatal()
	}
	if !union.Contains(NewRecord("ni hao", "ni hao")) {
		t.Fatal()
	}
	if len(union.issuerSerial) != 3 {
		t.Fatal()
	}
	if len(union.subjectKeyHash) != 3 {
		t.Fatal()
	}
}

func TestSetImpl_Intersection(t *testing.T) {
	a := NewDynamicSetImpl()
	b := NewDynamicSetImpl()
	a.Add(NewRecord("hi", ""))
	a.Add(NewRecord("", "hi"))
	b.Add(NewRecord("hi", ""))
	b.Add(NewRecord("hello", ""))
	intersection := a.Intersection(b).(*SetImpl)
	if !intersection.Contains(NewRecord("hi", "")) {
		t.Fatal()
	}
	if len(intersection.issuerSerial) != 1 {
		t.Fatal()
	}
	if len(intersection.subjectKeyHash) != 0 {
		t.Fatal()
	}
}

func TestSetImpl_Intersection2(t *testing.T) {
	a := NewDynamicSetImpl()
	b := NewDynamicSetImpl()
	a.Add(NewRecord("hi", ""))
	a.Add(NewRecord("", "hi"))
	a.Add(NewRecord("ni hao", "ni hao"))
	b.Add(NewRecord("hi", ""))
	b.Add(NewRecord("hello", ""))
	b.Add(NewRecord("ni hao", "ni hao"))
	intersection := a.Intersection(b).(*SetImpl)
	if !intersection.Contains(NewRecord("hi", "")) {
		t.Fatal()
	}
	if !intersection.Contains(NewRecord("ni hao", "ni hao")) {
		t.Fatal()
	}
	if len(intersection.issuerSerial) != 2 {
		t.Fatal()
	}
	if len(intersection.subjectKeyHash) != 1 {
		t.Fatal()
	}
}

func TestSetImpl_Intersection3(t *testing.T) {
	a := NewDynamicSetImpl()
	b := NewDynamicSetImpl()
	a.Add(NewRecord("hi", ""))
	a.Add(NewRecord("", "hi"))
	b.Add(NewRecord("hi!!!!!", ""))
	b.Add(NewRecord("hello", ""))
	intersection := a.Intersection(b).(*SetImpl)
	if len(intersection.issuerSerial) != 0 {
		t.Fatal()
	}
	if len(intersection.subjectKeyHash) != 0 {
		t.Fatal()
	}
}

func TestSetImpl_Difference(t *testing.T) {
	a := NewDynamicSetImpl()
	b := NewDynamicSetImpl()
	a.Add(NewRecord("hi", ""))
	a.Add(NewRecord("", "hi"))
	b.Add(NewRecord("hi", ""))
	b.Add(NewRecord("hello", ""))
	difference := a.Difference(b).(*SetImpl)
	if !difference.Contains(NewRecord("", "hi")) {
		t.Fatal()
	}
	if len(difference.issuerSerial) != 0 {
		t.Fatal()
	}
	if len(difference.subjectKeyHash) != 1 {
		t.Fatal()
	}
}

func TestSetImpl_Difference2(t *testing.T) {
	a := NewDynamicSetImpl()
	b := NewDynamicSetImpl()
	a.Add(NewRecord("hi", ""))
	b.Add(NewRecord("", "hi"))
	b.Add(NewRecord("hello", ""))
	difference := a.Difference(b).(*SetImpl)
	if !difference.Contains(NewRecord("hi", "")) {
		t.Fatal()
	}
	if len(difference.issuerSerial) != 1 {
		t.Fatal()
	}
	if len(difference.subjectKeyHash) != 0 {
		t.Fatal()
	}
}

func TestSetImpl_Difference3(t *testing.T) {
	a := NewDynamicSetImpl()
	b := NewDynamicSetImpl()
	a.Add(NewRecord("hi", ""))
	a.Add(NewRecord("", "hi"))
	b.Add(NewRecord("hi", ""))
	b.Add(NewRecord("hello", "hi"))
	difference := a.Difference(b).(*SetImpl)
	if difference.Contains(NewRecord("", "hi")) {
		t.Fatal()
	}
	if len(difference.issuerSerial) != 0 {
		t.Fatal()
	}
	if len(difference.subjectKeyHash) != 0 {
		t.Fatal()
	}
}
