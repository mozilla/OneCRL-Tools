/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crlsetcheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/crlset"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"
	"github.com/zmap/zcrypto/x509"
)

var now = time.Date(2026, time.October, 27, 0, 0, 0, 0, time.UTC)

type ca struct {
	cert *stdx509.Certificate
	// The same certificate, as parsed by zcrypto.
	zcert *x509.Certificate
	key   *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string, serial int64, parent *ca, eku []stdx509.ExtKeyUsage) *ca {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &stdx509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              stdx509.KeyUsageCertSign,
		ExtKeyUsage:           eku,
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := stdx509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	zcert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ca{cert: cert, zcert: zcert, key: key}
}

func (c *ca) spkiHash() [32]byte {
	return sha256.Sum256(c.cert.RawSubjectPublicKeyInfo)
}

func (c *ca) serial() []byte {
	return crlset.NormalizeSerial(c.cert.SerialNumber.Bytes())
}

func (c *ca) revoked(date, status string) *ccadb.Certificate {
	return &ccadb.Certificate{
		DateOfRevocation: date,
		OneCRLStatus:     status,
		PemInfo:          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})),
	}
}

func (c *ca) issuerSerialRecord() *onecrl.Record {
	serial, _ := utils.RawSerialBytes(c.cert.RawTBSCertificate)
	return &onecrl.Record{IssuerName: utils.B64Encode(c.cert.RawIssuer), SerialNumber: utils.B64Encode(serial)}
}

func (c *ca) subjectKeyHashRecord() *onecrl.Record {
	hash := c.spkiHash()
	return &onecrl.Record{Subject: utils.B64Encode(c.cert.RawSubject), PubKeyHash: utils.B64Encode(hash[:])}
}

func TestCheck(t *testing.T) {
	tls := []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}
	root := newCA(t, "Included Root", 1, nil, nil)
	// The serial number has its high bit set, so its DER encoding has a leading zero byte.
	missing := newCA(t, "Missing From OneCRL", 0x80aa, root, tls)
	inOneCRL := newCA(t, "In OneCRL", 3, root, nil)
	inOneCRLBySubject := newCA(t, "In OneCRL By Subject", 4, root, tls)
	smime := newCA(t, "S/MIME", 5, root, []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageEmailProtection})
	recent := newCA(t, "Recently Revoked", 6, root, tls)
	notApplicable := newCA(t, "Not Applicable", 7, root, tls)
	notRevoked := newCA(t, "Not Revoked In CCADB", 8, root, tls)
	unknownRoot := newCA(t, "Unknown Root", 9, nil, nil)

	in := &Input{
		CRLSet: &crlset.CRLSet{Entries: map[[32]byte][][]byte{
			root.spkiHash(): {
				missing.serial(), inOneCRL.serial(), inOneCRLBySubject.serial(), smime.serial(),
				recent.serial(), notApplicable.serial(), notRevoked.serial(), {0x99},
			},
			// Revocations of certificates issued by intermediates are presumed to be end-entity certificates.
			notRevoked.spkiHash():  {{0x98}},
			unknownRoot.spkiHash(): {{0x97}},
		}},
		Roots:         []*x509.Certificate{root.zcert},
		Intermediates: []*x509.Certificate{notRevoked.zcert},
		Revoked: []*ccadb.Certificate{
			missing.revoked("2026 Sep 29", ""),
			inOneCRL.revoked("2026 Sep 29", "Added to OneCRL"),
			inOneCRLBySubject.revoked("2026 Sep 29", "Added to OneCRL"),
			smime.revoked("2026 Sep 29", ""),
			recent.revoked("2026 Oct 20", "Ready to Add"),
			notApplicable.revoked("2026 Sep 29", "Not Applicable"),
		},
		OneCRL: []*onecrl.Record{inOneCRL.issuerSerialRecord(), inOneCRLBySubject.subjectKeyHashRecord()},
	}
	findings := Check(in)

	rootHash := root.spkiHash()
	expected := map[string]Kind{
		NotInOneCRL.key(missing):        NotInOneCRL,
		NotInOneCRL.key(recent):         NotInOneCRL,
		CCADBNotRevoked.key(notRevoked): CCADBNotRevoked,
		string(Undisclosed) + ":" + hex.EncodeToString(rootHash[:]) + ":" + "99": Undisclosed,
	}
	if len(findings) != len(expected) {
		for _, f := range findings {
			t.Logf("finding: %s (%s)", f.Key(), f.Subject)
		}
		t.Fatalf("expected %d findings, got %d", len(expected), len(findings))
	}
	for _, f := range findings {
		kind, ok := expected[f.Key()]
		if !ok || kind != f.Kind {
			t.Errorf("unexpected finding %s", f.Key())
		}
		if f.Key() == NotInOneCRL.key(missing) && (f.Subject != "CN=Missing From OneCRL" || f.Serial != "80aa" || f.RevocationDate != "2026 Sep 29") {
			t.Errorf("unexpected details %+v", f)
		}
	}
}

func (k Kind) key(c *ca) string {
	fingerprint := sha256.Sum256(c.cert.Raw)
	return string(k) + ":" + hex.EncodeToString(fingerprint[:])
}

// The CCADB has certificates that Go's crypto/x509 rejects.
func TestParseCertificateLenient(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &stdx509.Certificate{
		SerialNumber:            big.NewInt(1),
		Subject:                 pkix.Name{CommonName: "Malformed Name Constraint"},
		NotBefore:               now.Add(-time.Hour),
		NotAfter:                now.Add(time.Hour),
		IsCA:                    true,
		BasicConstraintsValid:   true,
		PermittedEmailAddresses: []string{"@suva.ch"},
	}
	der, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdx509.ParseCertificate(der); err == nil {
		t.Fatal("expected crypto/x509 to reject the certificate")
	}
	record := &ccadb.Certificate{PemInfo: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	cert, err := record.ParseCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if utils.NameString(cert.RawSubject) != "CN=Malformed Name Constraint" {
		t.Errorf("unexpected subject %s", utils.NameString(cert.RawSubject))
	}
	if _, err := (&ccadb.Certificate{PemInfo: "''"}).ParseCertificate(); err != ccadb.ErrNoCertificate {
		t.Errorf("expected ErrNoCertificate, got %v", err)
	}
}
