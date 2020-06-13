/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"
)

func TestNormalize(t *testing.T) {
	got := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: []int{5, 4, 3, 2}},
			pkix.AttributeTypeAndValue{Type: []int{5, 5, 4}},
			pkix.AttributeTypeAndValue{Type: []int{2, 2}},
			pkix.AttributeTypeAndValue{Type: []int{1, 2, 3}},
			pkix.AttributeTypeAndValue{Type: []int{1}},
		},
	}
	want := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: []int{1}},
			pkix.AttributeTypeAndValue{Type: []int{2, 2}},
			pkix.AttributeTypeAndValue{Type: []int{1, 2, 3}},
			pkix.AttributeTypeAndValue{Type: []int{5, 5, 4}},
			pkix.AttributeTypeAndValue{Type: []int{5, 4, 3, 2}},
		},
	}
	Normalize(got)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected sort of OIDs, wanted %v got %v", want, got)
	}
}

type cmpTest struct {
	left  asn1.ObjectIdentifier
	right asn1.ObjectIdentifier
	want  bool
}

var cmpData = []cmpTest{
	{
		left:  asn1.ObjectIdentifier{1},
		right: asn1.ObjectIdentifier{2},
		want:  true,
	},
	{
		left:  asn1.ObjectIdentifier{2},
		right: asn1.ObjectIdentifier{1},
		want:  false,
	},
	{
		left:  asn1.ObjectIdentifier{1},
		right: asn1.ObjectIdentifier{1},
		want:  false,
	},
	{
		left:  asn1.ObjectIdentifier{1},
		right: asn1.ObjectIdentifier{1, 1},
		want:  true,
	},
	{
		left:  asn1.ObjectIdentifier{1, 1},
		right: asn1.ObjectIdentifier{2},
		want:  false,
	},
	{
		left:  asn1.ObjectIdentifier{1, 2, 3, 4},
		right: asn1.ObjectIdentifier{1, 2, 4, 3},
		want:  true,
	},
	{
		left:  asn1.ObjectIdentifier{1, 2, 4, 3},
		right: asn1.ObjectIdentifier{1, 2, 3, 4},
		want:  false,
	},
}

func TestCmpOID(t *testing.T) {
	for _, data := range cmpData {
		got := CmpOID(data.left, data.right)
		if got != data.want {
			t.Errorf("unexpected comparison answer, wanted %v got %v.", data.want, got)
			t.Errorf("left: %v, right %v", data.left, data.right)
		}
	}
}
