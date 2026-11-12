/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crlset

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"
)

func encode(header string, entries map[[32]byte][][]byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(len(header)))
	b.WriteString(header)
	for parent, serials := range entries {
		b.Write(parent[:])
		binary.Write(&b, binary.LittleEndian, uint32(len(serials)))
		for _, serial := range serials {
			b.WriteByte(byte(len(serial)))
			b.Write(serial)
		}
	}
	return b.Bytes()
}

const header = `{"Version":0,"ContentType":"CRLSet","Sequence":42,"NumParents":1}`

func TestParse(t *testing.T) {
	parent := [32]byte{1, 2, 3}
	set, err := Parse(encode(header, map[[32]byte][][]byte{
		parent: {{0x01, 0x02}, {0x00, 0x80, 0x01}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if set.Header.Sequence != 42 {
		t.Errorf("expected sequence 42, got %d", set.Header.Sequence)
	}
	serials := set.Entries[parent]
	if len(serials) != 2 || !bytes.Equal(serials[0], []byte{0x01, 0x02}) || !bytes.Equal(serials[1], []byte{0x80, 0x01}) {
		t.Errorf("unexpected serials %x", serials)
	}
}

func TestParseTruncated(t *testing.T) {
	b := encode(header, map[[32]byte][][]byte{{1}: {{0x01, 0x02}}})
	for i := 0; i < len(b); i++ {
		if _, err := Parse(b[:i]); err == nil && i != 2+len(header) {
			t.Errorf("expected an error when truncated to %d bytes", i)
		}
	}
}

func TestParseWrongContentType(t *testing.T) {
	if _, err := Parse(encode(`{"ContentType":"Other"}`, nil)); err == nil {
		t.Error("expected an error")
	}
}

func TestFromCRX3(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, _ := zw.Create("manifest.json")
	w.Write([]byte("{}"))
	w, _ = zw.Create("crl-set")
	w.Write(encode(header, map[[32]byte][][]byte{{1}: {{0x01}}}))
	zw.Close()

	protobufHeader := []byte("not really a protobuf")
	var crx bytes.Buffer
	crx.WriteString("Cr24")
	binary.Write(&crx, binary.LittleEndian, uint32(3))
	binary.Write(&crx, binary.LittleEndian, uint32(len(protobufHeader)))
	crx.Write(protobufHeader)
	crx.Write(archive.Bytes())

	set, err := FromCRX3(crx.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if set.Header.Sequence != 42 || len(set.Entries) != 1 {
		t.Errorf("unexpected CRLSet %+v", set)
	}
	if _, err := FromCRX3(archive.Bytes()); err == nil {
		t.Error("expected an error for a bare zip archive")
	}
}
