/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"bytes"
	"testing"
)

func assertBytes(t *testing.T, data string, expected []byte) {
	result, err := B64Decode(data)
	if err != nil {
		t.Errorf("Expected %s to decode to %v but error: %v", data, expected, err)
		return
	}
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %s to decode to %v but got: %v", data, expected, result)
	}
}

func TestBase64Decoder(t *testing.T) {
	// Tolerate spaces
	assertBytes(t, "b2theSB0aGVyZQ==", []byte("okay there"))
	assertBytes(t, "b2theSB0aGVyZQ== ", []byte("okay there"))
	assertBytes(t, " b2theSB0aGVyZQ==", []byte("okay there"))
	assertBytes(t, " b2theSB0aGVyZQ== ", []byte("okay there"))

	// Handle high bytes
	assertBytes(t, "/+7dzLuqmYg=", []byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88})

	// Handle having no padding
	assertBytes(t, "/+7dzLuqmYg", []byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88})
}
