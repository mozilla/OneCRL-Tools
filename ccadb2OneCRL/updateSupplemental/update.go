/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"fmt"
	"sort"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/prune"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"
)

// crtshCert is a certificate found on crt.sh.
type crtshCert struct {
	id   string
	cert *x509.Certificate
}

// lookupFunc finds certificates with the given serial numbers (without
// leading zero bytes) on crt.sh. It may return certificates from any issuer.
type lookupFunc func(serials [][]byte) ([]crtshCert, error)

type result struct {
	// The new contents of supplemental.json.
	entries []prune.SupplementalEntry
	// Entries that were removed because they are no longer in OneCRL.
	removed []prune.SupplementalEntry
	// Entries that were added.
	added []prune.SupplementalEntry
	// Issuer:serial records whose certificate could not be found.
	unknown []*onecrl.Record
}

// The extension that marks a precertificate (RFC 6962, section 3.1).
var ctPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

func isPrecertificate(cert *x509.Certificate) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(ctPoison) {
			return true
		}
	}
	return false
}

// update returns the new contents of supplemental.json.
//
// Existing entries are kept as long as OneCRL has a record for them. An entry
// is added for every other issuer:serial record in OneCRL that the CCADB
// report of revoked intermediates does not cover, if its certificate is in
// one of the CCADB's other reports or on crt.sh.
func update(existing []prune.SupplementalEntry, records []*onecrl.Record, revoked, other []*x509.Certificate, crtsh lookupFunc) (*result, error) {
	res := &result{}
	inOneCRL := make(map[string]bool)
	for _, record := range records {
		if k, ok := prune.Key(record); ok {
			inOneCRL[k] = true
		}
	}

	covered := make(map[string]bool)
	for _, entry := range existing {
		k, ok := prune.Key(&onecrl.Record{IssuerName: entry.IssuerName, SerialNumber: entry.SerialNumber})
		if !ok {
			return nil, fmt.Errorf("malformed entry in supplemental.json for serial %s", entry.Serial)
		}
		if !inOneCRL[k] {
			res.removed = append(res.removed, entry)
			continue
		}
		if covered[k] {
			continue
		}
		covered[k] = true
		res.entries = append(res.entries, entry)
	}
	for _, cert := range revoked {
		if c, err := prune.FromX509(cert); err == nil {
			covered[c.Key()] = true
		}
	}

	// The records that need a supplemental entry, one per issuer:serial entry.
	missing := make(map[string]*onecrl.Record)
	for _, record := range records {
		if k, ok := prune.Key(record); ok && !covered[k] && missing[k] == nil {
			missing[k] = record
		}
	}

	found := make(map[string]*prune.Certificate)
	consider := func(cert *x509.Certificate, source, crtshID string) {
		c, err := prune.FromX509(cert)
		if err != nil || missing[c.Key()] == nil {
			return
		}
		c.Source, c.CrtshID = source, crtshID
		existing, ok := found[c.Key()]
		// Prefer the certificate that expires last, and a certificate over
		// its precertificate (which has the same expiry).
		if !ok || c.NotAfter.After(existing.NotAfter) ||
			(c.NotAfter.Equal(existing.NotAfter) && existing.Source == source && !isPrecertificate(cert)) {
			found[c.Key()] = c
		}
	}
	for _, cert := range other {
		consider(cert, "ccadb", "")
	}

	serials := make([][]byte, 0)
	for k, record := range missing {
		if found[k] != nil {
			continue
		}
		serial, _ := utils.B64Decode(record.SerialNumber)
		serials = append(serials, normalizeSerial(serial))
	}
	if len(serials) > 0 && crtsh != nil {
		certs, err := crtsh(serials)
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			// Certificates from the CCADB take precedence.
			if k, ok := keyOf(c.cert); ok && found[k] != nil && found[k].Source == "ccadb" {
				continue
			}
			consider(c.cert, "crt.sh", c.id)
		}
	}

	for k, record := range missing {
		cert := found[k]
		if cert == nil {
			res.unknown = append(res.unknown, record)
			continue
		}
		entry := prune.SupplementalEntry{
			IssuerName:   record.IssuerName,
			SerialNumber: record.SerialNumber,
			Issuer:       utils.NameString(cert.Issuer),
			Serial:       fmt.Sprintf("%X", normalizeSerial(cert.Serial)),
			Bug:          record.Details.Bug,
			Certificate: &prune.SupplementalCertificate{
				Subject:  cert.Subject,
				NotAfter: cert.NotAfter.UTC(),
				Source:   cert.Source,
				CrtshID:  cert.CrtshID,
			},
		}
		res.entries = append(res.entries, entry)
		res.added = append(res.added, entry)
	}

	sortEntries(res.entries)
	sortEntries(res.added)
	sortEntries(res.removed)
	sort.Slice(res.unknown, func(i, j int) bool {
		return res.unknown[i].IssuerName+res.unknown[i].SerialNumber < res.unknown[j].IssuerName+res.unknown[j].SerialNumber
	})
	return res, nil
}

func keyOf(cert *x509.Certificate) (string, bool) {
	c, err := prune.FromX509(cert)
	if err != nil {
		return "", false
	}
	return c.Key(), true
}

func sortEntries(entries []prune.SupplementalEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Issuer != entries[j].Issuer {
			return entries[i].Issuer < entries[j].Issuer
		}
		return entries[i].Serial < entries[j].Serial
	})
}

// normalizeSerial strips leading zero bytes from a serial number.
func normalizeSerial(serial []byte) []byte {
	for len(serial) > 1 && serial[0] == 0 {
		serial = serial[1:]
	}
	return serial
}
