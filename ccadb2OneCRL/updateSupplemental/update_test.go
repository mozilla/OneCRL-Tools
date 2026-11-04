/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/prune"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"
)

var now = time.Date(2026, time.November, 4, 0, 0, 0, 0, time.UTC)

var issuerKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

var issuer = &stdx509.Certificate{
	SerialNumber:          big.NewInt(1),
	Subject:               pkix.Name{CommonName: "Issuer"},
	NotBefore:             now.Add(-10 * 365 * 24 * time.Hour),
	NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
	IsCA:                  true,
	BasicConstraintsValid: true,
}

func newCert(t *testing.T, serial int64, notAfter time.Time, precertificate bool) *x509.Certificate {
	template := &stdx509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "Revoked"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	if precertificate {
		template.ExtraExtensions = []pkix.Extension{{
			Id:       stdasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
			Critical: true,
			Value:    []byte{0x05, 0x00},
		}}
	}
	der, err := stdx509.CreateCertificate(rand.Reader, template, issuer, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func record(cert *x509.Certificate, bug string) *onecrl.Record {
	serial, _ := utils.RawSerialBytes(cert.RawTBSCertificate)
	r := &onecrl.Record{IssuerName: utils.B64Encode(cert.RawIssuer), SerialNumber: utils.B64Encode(serial)}
	r.Details.Bug = bug
	return r
}

func entryFor(cert *x509.Certificate) prune.SupplementalEntry {
	r := record(cert, "")
	return prune.SupplementalEntry{
		IssuerName:   r.IssuerName,
		SerialNumber: r.SerialNumber,
		Certificate:  &prune.SupplementalCertificate{NotAfter: cert.NotAfter, Source: "crt.sh"},
	}
}

func TestUpdate(t *testing.T) {
	year := 365 * 24 * time.Hour
	stillInOneCRL := newCert(t, 1, now.Add(-year), false)
	removedFromOneCRL := newCert(t, 2, now.Add(-year), false)
	coveredByRevoked := newCert(t, 3, now.Add(-year), false)
	inOtherReport := newCert(t, 4, now.Add(year), false)
	onCrtsh := newCert(t, 0x80aa, now.Add(-year), false)
	onCrtshPrecert := newCert(t, 0x80aa, now.Add(-year), true)
	unknown := newCert(t, 6, now.Add(-year), false)

	existing := []prune.SupplementalEntry{entryFor(stillInOneCRL), entryFor(removedFromOneCRL)}
	records := []*onecrl.Record{
		record(stillInOneCRL, "1"),
		record(coveredByRevoked, "3"),
		record(inOtherReport, "4"),
		record(onCrtsh, "5"),
		// Staging and production both have a record for this entry.
		record(onCrtsh, "5"),
		record(unknown, "6"),
		{Subject: "c3ViamVjdA==", PubKeyHash: "aGFzaA=="},
	}
	var queried [][]byte
	crtsh := func(serials [][]byte) ([]crtshCert, error) {
		queried = serials
		return []crtshCert{{id: "10", cert: onCrtshPrecert}, {id: "11", cert: onCrtsh}}, nil
	}

	res, err := update(existing, records, []*x509.Certificate{coveredByRevoked}, []*x509.Certificate{inOtherReport}, crtsh)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.removed) != 1 || res.removed[0].SerialNumber != entryFor(removedFromOneCRL).SerialNumber {
		t.Errorf("expected the entry that is no longer in OneCRL to be removed, got %+v", res.removed)
	}
	if len(res.unknown) != 1 || res.unknown[0].Details.Bug != "6" {
		t.Errorf("expected one unknown record, got %+v", res.unknown)
	}
	// Only the serial numbers that were not found in the CCADB are looked up on crt.sh.
	if len(queried) != 2 {
		t.Errorf("expected 2 serial numbers to be looked up on crt.sh, got %d", len(queried))
	}
	for _, serial := range queried {
		if bytes.Equal(serial, []byte{4}) {
			t.Error("a certificate in the CCADB's other reports was looked up on crt.sh")
		}
		if serial[0] == 0 {
			t.Errorf("serial number %X was not normalized", serial)
		}
	}
	added := make(map[string]prune.SupplementalEntry)
	for _, entry := range res.added {
		added[entry.Serial] = entry
	}
	if len(res.added) != 2 {
		t.Fatalf("expected 2 added entries, got %+v", res.added)
	}
	if e := added["04"]; e.Certificate == nil || e.Certificate.Source != "ccadb" || e.Bug != "4" {
		t.Errorf("unexpected entry for a certificate in the CCADB's other reports: %+v", e)
	}
	if e := added["80AA"]; e.Certificate == nil || e.Certificate.Source != "crt.sh" || e.Certificate.CrtshID != "11" {
		t.Errorf("expected the certificate rather than its precertificate: %+v", e.Certificate)
	}
	if len(res.entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(res.entries))
	}
}

func TestUpdateWithoutChanges(t *testing.T) {
	cert := newCert(t, 1, now.Add(-time.Hour), false)
	called := false
	crtsh := func(serials [][]byte) ([]crtshCert, error) {
		called = true
		return nil, nil
	}
	res, err := update([]prune.SupplementalEntry{entryFor(cert)}, []*onecrl.Record{record(cert, "")}, nil, nil, crtsh)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("crt.sh was queried even though every entry is covered")
	}
	if len(res.entries) != 1 || len(res.added) != 0 || len(res.removed) != 0 || len(res.unknown) != 0 {
		t.Errorf("expected no changes, got %+v", res)
	}
}
