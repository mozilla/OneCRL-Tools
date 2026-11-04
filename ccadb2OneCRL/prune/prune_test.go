/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package prune

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zmap/zcrypto/x509"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
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

func newCert(t *testing.T, serial int64, notAfter time.Time) *x509.Certificate {
	template := &stdx509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "Revoked Intermediate"},
		NotBefore:             notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
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

func issuerSerialRecord(cert *x509.Certificate, leadingZero bool) *onecrl.Record {
	serial, _ := utils.RawSerialBytes(cert.RawTBSCertificate)
	if leadingZero {
		serial = append([]byte{0}, serial...)
	}
	return &onecrl.Record{IssuerName: utils.B64Encode(cert.RawIssuer), SerialNumber: utils.B64Encode(serial)}
}

func TestFind(t *testing.T) {
	day := 24 * time.Hour
	expiredLongAgo := newCert(t, 1, now.Add(-365*day))
	withinGrace := newCert(t, 2, now.Add(-29*day))
	justPastGrace := newCert(t, 3, now.Add(-31*day))
	valid := newCert(t, 4, now.Add(365*day))
	// Two certificates with the same issuer and serial number, one of which is still valid.
	twinExpired := newCert(t, 5, now.Add(-365*day))
	twinValid := newCert(t, 5, now.Add(365*day))
	// The serial number of this certificate has its high bit set.
	highBit := newCert(t, 0x80aa, now.Add(-365*day))
	unknown := newCert(t, 6, now.Add(-365*day))

	records := []*onecrl.Record{
		issuerSerialRecord(expiredLongAgo, false),
		// Staging and production both have a record for this entry.
		issuerSerialRecord(expiredLongAgo, false),
		issuerSerialRecord(withinGrace, false),
		issuerSerialRecord(justPastGrace, false),
		issuerSerialRecord(valid, false),
		issuerSerialRecord(twinExpired, false),
		issuerSerialRecord(highBit, true),
		issuerSerialRecord(unknown, false),
		{Subject: "c3ViamVjdA==", PubKeyHash: "aGFzaA=="},
	}
	var certs []*Certificate
	for _, c := range []*x509.Certificate{expiredLongAgo, withinGrace, justPastGrace, valid, twinExpired, twinValid, highBit} {
		cert, err := FromX509(c)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}

	removals := Find(records, certs, now)
	got := make(map[string]bool)
	for _, r := range removals {
		k, _ := Key(r.Record)
		if got[k] {
			t.Errorf("entry returned more than once: %X", r.Cert.Serial)
		}
		got[k] = true
	}
	for _, c := range []*x509.Certificate{expiredLongAgo, justPastGrace, highBit} {
		k, _ := Key(issuerSerialRecord(c, false))
		if !got[k] {
			t.Errorf("expected serial %v to be removed", c.SerialNumber)
		}
	}
	if len(removals) != 3 {
		t.Errorf("expected 3 removals, got %d", len(removals))
	}
}

func TestSupplemental(t *testing.T) {
	day := 24 * time.Hour
	expired := newCert(t, 7, now.Add(-365*day))
	unknownCert := newCert(t, 8, now.Add(-365*day))
	entry := `
  {
    "issuerName": "` + issuerSerialRecord(expired, true).IssuerName + `",
    "serialNumber": "` + issuerSerialRecord(expired, true).SerialNumber + `",
    "issuer": "CN=Issuer",
    "serial": "07",
    "bug": "https://bugzilla.mozilla.org/show_bug.cgi?id=1",
    "certificate": {
      "subject": "CN=Revoked Intermediate",
      "not_after": "` + expired.NotAfter.UTC().Format(time.RFC3339) + `",
      "source": "crt.sh",
      "crtsh_id": "1234"
    }
  }`
	certs, err := parseSupplemental([]byte("[" + entry + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].CrtshID != "1234" {
		t.Fatalf("expected one certificate, got %+v", certs)
	}
	records := []*onecrl.Record{issuerSerialRecord(expired, false), issuerSerialRecord(unknownCert, false)}
	removals := Find(records, certs, now)
	if len(removals) != 1 || removals[0].Cert.Source != "crt.sh" {
		t.Errorf("expected the entry with a known certificate to be removed, got %d removals", len(removals))
	}

	// Every entry must have a certificate.
	withoutCertificate := `
  {
    "issuerName": "` + issuerSerialRecord(unknownCert, false).IssuerName + `",
    "serialNumber": "` + issuerSerialRecord(unknownCert, false).SerialNumber + `",
    "issuer": "CN=Issuer",
    "serial": "08",
    "bug": ""
  }`
	if _, err := parseSupplemental([]byte("[" + entry + "," + withoutCertificate + "]")); err == nil {
		t.Error("expected an error for an entry without a certificate")
	}
}

// The embedded supplemental.json must parse, and every certificate in it must be usable.
func TestEmbeddedSupplemental(t *testing.T) {
	certs, err := Supplemental()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("supplemental.json has no certificates")
	}
	for _, c := range certs {
		if len(c.Issuer) == 0 || len(c.Serial) == 0 || c.NotAfter.IsZero() || (c.Source != "ccadb" && c.Source != "crt.sh") {
			t.Errorf("incomplete certificate in supplemental.json: %+v", c)
		}
	}
}
