/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Package prune finds OneCRL entries that are no longer needed because the
// certificates they revoke have expired.
//
// Firefox checks the validity period of every certificate in a TLS chain, so
// once a certificate has expired its OneCRL entry has no effect. We wait for a
// grace period after expiry before removing an entry, to accommodate clients
// with inaccurate clocks.
//
// Only issuer:serial entries are pruned. A subject:pubKeyHash entry revokes
// every certificate with a given key, including certificates that we do not
// know about, so it is never pruned. Neither is an issuer:serial entry that
// does not match any known certificate.
package prune

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/pkg/errors"
	"github.com/zmap/zcrypto/x509"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"
)

// GracePeriod is how long an entry is kept after the certificate it revokes has expired.
const GracePeriod = 30 * 24 * time.Hour

// Certificate is what we need to know about a certificate to decide whether
// its OneCRL entry can be removed.
type Certificate struct {
	// The DER encoded issuer name and the contents of the DER encoded serial number.
	Issuer []byte
	Serial []byte
	// The remaining fields describe the certificate in bug reports.
	NotAfter time.Time
	Subject  string
	// Where we learned about the certificate: "ccadb" or "crt.sh".
	Source  string
	CrtshID string
}

// FromX509 describes a certificate from the CCADB.
func FromX509(cert *x509.Certificate) (*Certificate, error) {
	serial, err := utils.RawSerialBytes(cert.RawTBSCertificate)
	if err != nil {
		return nil, err
	}
	return &Certificate{
		Issuer:   cert.RawIssuer,
		Serial:   serial,
		NotAfter: cert.NotAfter,
		Subject:  utils.NameString(cert.RawSubject),
		Source:   "ccadb",
	}, nil
}

// Removal is an issuer:serial entry that can be removed from OneCRL.
type Removal struct {
	// A record for the entry. Staging and production may each have a record for the same entry.
	Record *onecrl.Record
	// The certificate with the entry's issuer and serial number that expires last.
	Cert *Certificate
}

// Expired reports whether a certificate that expires at notAfter expired more than GracePeriod before now.
func Expired(notAfter time.Time, now time.Time) bool {
	return now.After(notAfter.Add(GracePeriod))
}

// Key identifies an issuer:serial entry independently of how its serial number is encoded.
// It returns false for subject:pubKeyHash records and for records that cannot be decoded.
func Key(record *onecrl.Record) (string, bool) {
	if record.IssuerName == "" || record.SerialNumber == "" {
		return "", false
	}
	issuer, err := utils.B64Decode(record.IssuerName)
	if err != nil {
		return "", false
	}
	serial, err := utils.B64Decode(record.SerialNumber)
	if err != nil {
		return "", false
	}
	return key(issuer, serial), true
}

func key(issuer, serial []byte) string {
	// DER requires a leading zero byte when the high bit of the first byte is
	// set, but not every OneCRL entry has one.
	for len(serial) > 1 && serial[0] == 0 {
		serial = serial[1:]
	}
	return string(issuer) + "|" + string(serial)
}

// Find returns the issuer:serial entries among records for which every
// certificate in certs with the same issuer and serial number expired more
// than GracePeriod before now. Entries without any such certificate are not
// returned. Each entry is returned once, even if several records share it.
func Find(records []*onecrl.Record, certs []*Certificate, now time.Time) []*Removal {
	latest := make(map[string]*Certificate)
	for _, cert := range certs {
		k := key(cert.Issuer, cert.Serial)
		if existing, ok := latest[k]; !ok || cert.NotAfter.After(existing.NotAfter) {
			latest[k] = cert
		}
	}
	seen := make(map[string]bool)
	removals := make([]*Removal, 0)
	for _, record := range records {
		k, ok := Key(record)
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		cert, ok := latest[k]
		if !ok || !Expired(cert.NotAfter, now) {
			continue
		}
		removals = append(removals, &Removal{Record: record, Cert: cert})
	}
	sort.Slice(removals, func(i, j int) bool {
		return removals[i].Cert.NotAfter.Before(removals[j].Cert.NotAfter)
	})
	return removals
}

// SupplementalEntry is an issuer:serial OneCRL entry that is not covered by
// the CCADB report of revoked intermediates, together with the certificate it
// revokes. Entries whose certificate is not known are not listed.
type SupplementalEntry struct {
	// The entry's values in OneCRL.
	IssuerName   string `json:"issuerName"`
	SerialNumber string `json:"serialNumber"`
	// The decoded issuer name and hex encoded serial number.
	Issuer string `json:"issuer"`
	Serial string `json:"serial"`
	// The bug that added the entry.
	Bug string `json:"bug"`
	// The revoked certificate.
	Certificate *SupplementalCertificate `json:"certificate"`
}

type SupplementalCertificate struct {
	Subject  string    `json:"subject"`
	NotAfter time.Time `json:"not_after"`
	Source   string    `json:"source"`
	CrtshID  string    `json:"crtsh_id,omitempty"`
}

//go:embed supplemental.json
var supplementalJSON []byte

// Supplemental returns the certificates of the entries in supplemental.json.
func Supplemental() ([]*Certificate, error) {
	return parseSupplemental(supplementalJSON)
}

func parseSupplemental(data []byte) ([]*Certificate, error) {
	var entries []SupplementalEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, errors.Wrap(err, "malformed supplemental.json")
	}
	certs := make([]*Certificate, 0, len(entries))
	for _, entry := range entries {
		if entry.Certificate == nil {
			return nil, fmt.Errorf("missing certificate in supplemental.json for serial %s", entry.Serial)
		}
		issuer, err := utils.B64Decode(entry.IssuerName)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("malformed issuerName in supplemental.json for serial %s", entry.Serial))
		}
		serial, err := utils.B64Decode(entry.SerialNumber)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("malformed serialNumber in supplemental.json for serial %s", entry.Serial))
		}
		certs = append(certs, &Certificate{
			Issuer:   issuer,
			Serial:   serial,
			NotAfter: entry.Certificate.NotAfter,
			Subject:  entry.Certificate.Subject,
			Source:   entry.Certificate.Source,
			CrtshID:  entry.Certificate.CrtshID,
		})
	}
	return certs, nil
}
