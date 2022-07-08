/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

type tbsCertWithRawSerial struct {
	Raw          asn1.RawContent
	Version      asn1.RawValue `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber asn1.RawValue
}

// Extract the raw bytes of the serial number field from a tbsCertificate.
func RawSerialBytes(rawTBSCertificate []byte) ([]byte, error) {
	var tbsCert tbsCertWithRawSerial
	_, err := asn1.Unmarshal(rawTBSCertificate, &tbsCert)
	if err != nil {
		return nil, err
	}
	return tbsCert.SerialNumber.Bytes, nil
}

// B64Decode attempts to decode the give string first as an
// RFC 4648 encoded string (with padding). If that fails, then
// RFC 4648 section 3.2 (without padding) is attempted. If
// RFC 4648 section 3.2 fails as well, then the original
// error message (with padding) is returned.
//
// All provided strings are first trimmed of whitespace
// before attempting decoding.
func B64Decode(b64 string) ([]byte, error) {
	// Some OneCRL entries have a trailing space.
	b64trimmed := strings.TrimSpace(b64)
	decoded, err := base64.StdEncoding.DecodeString(b64trimmed)
	if err == nil {
		return decoded, nil
	}
	// There are a handful entries that you will sometime find that
	// are raw encoded (with no padding). So give that a shot
	// as a fallback.
	decoded, err2 := base64.RawStdEncoding.DecodeString(b64trimmed)
	if err2 == nil {
		return decoded, nil
	}
	return nil, errors.Wrap(err, fmt.Sprintf("b64 decode error for '%s'", b64))
}

func B64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}
