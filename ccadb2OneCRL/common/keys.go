/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package common

import (
	"crypto/x509/pkix"
	"fmt"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"
)

// The types in this file define a normalized identifier representation of the data found in the CCADB and that
// found in OneCRL. This sort of normalization is required
// largely because the CCADB contains all relevant information (via holding a copy of the
// certificate itself), however OneCRL has only either a combination of the IssuerName:SerialNumber
// or the SubjectName:KeyHash as identifying information (and the CCADB does not know which type it holds).
//
// So if you want check whether or not an entry from the CCADB is present in OneCRL, you must
// obtain both its IssuerName:SerialNumber AND SubjectName:KeyHash values and lookup OneCRL for
// either (because there is no information in the CCADB as to which one it is in OneCRL).

type EntryType string

// IssuerSerial is an alias for a string that is formatted as "<IssuerName>,<B64 Serial>"
type IssuerSerial EntryType

// IssuerSerial is an alias for a string that is formatted as "<SubjectName>,<B64 Key Hash>"
type SubjectKeyHash EntryType

func NewIssuerSerial(issuer *pkix.RDNSequence, serial []byte) IssuerSerial {
	return IssuerSerial(format(issuer, serial))
}

func NewSubjectKeyHash(subject *pkix.RDNSequence, hash []byte) SubjectKeyHash {
	return SubjectKeyHash(format(subject, hash))
}

func format(name *pkix.RDNSequence, data []byte) string {
	return fmt.Sprintf("%s,%s", name.String(), utils.B64Encode(data))
}
