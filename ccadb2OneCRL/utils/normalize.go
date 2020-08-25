/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

func Normalize(rdn *pkix.RDNSequence) {
	for _, set := range *rdn {
		sort.Slice(set, func(i, j int) bool {
			return CmpOID(set[i].Type, set[j].Type)
		})
	}
}

func CmpOID(left, right asn1.ObjectIdentifier) bool {
	if len(left) != len(right) {
		return len(left) < len(right)
	}
	for i, _ := range left {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return false
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
