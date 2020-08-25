/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/set"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"
	"github.com/pkg/errors"

	"github.com/gocarina/gocsv"
)

const source = "https://ccadb-public.secure.force.com/mozilla/PublicInterCertsReadyToAddToOneCRLPEMCSV"

type OneCRLStatus string

var ReadyToAdd OneCRLStatus = "Ready to Add"

type CCADB = []*Certificate

type Certificate struct {
	CAOwner                        string `csv:"CA Owner"`
	RevocationStatus               string `csv:"Revocation Status"`
	ReasonCode                     string `csv:"RFC 5280 Revocation Reason Code"`
	DateOfRevocation               string `csv:"Date of Revocation"`
	OneCRLStatus                   string `csv:"OneCRL Status"`
	OneCRLBugNumber                string `csv:"OneCRL Bug Number"`
	CertificateSerialNumber        string `csv:"Certificate Serial Number"`
	CaOwnerName                    string `csv:"CA Owner/Certificate Name"`
	CertificateIssuerName          string `csv:"Certificate Issuer Common Name"`
	CertificateIssuerOrganization  string `csv:"Certificate Issuer Organization"`
	CertificateSubjectCommonName   string `csv:"Certificate Subject Common Name"`
	CertificateSubjectOrganization string `csv:"Certificate Subject Organization"`
	Fingerprint                    string `csv:"SHA-256 Fingerprint"`
	SubjectSPKIHash                string `csv:"Subject + SPKI SHA256"`
	NotBefore                      string `csv:"Valid From [GMT]"`
	NotAfter                       string `csv:"Valid To [GMT]"`
	KeyAlgorithm                   string `csv:"Public Key Algorithm"`
	SignatureAlgorithm             string `csv:"Signature Hash Algorithm"`
	CRLs                           string `csv:"CRL URL(s)"`
	AlternativeCRL                 string `csv:"Alternate CRL"`
	Comments                       string `csv:"Comments"`
	PemInfo                        string `csv:"PEM Info"`
}

func Default() ([]*Certificate, error) {
	return FromURL(source)
}

func FromURL(url string) ([]*Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return FromReader(resp.Body)
}

func FromReader(reader io.Reader) ([]*Certificate, error) {
	report := make([]*Certificate, 0)
	return report, gocsv.Unmarshal(reader, &report)
}

// IssuerSerial parses the X.509 certificate retrieved from the CCADB,
// extracts the issuer (https://tools.ietf.org/html/rfc5280#section-4.1.2.4) and
// serial number (https://tools.ietf.org/html/rfc5280#section-4.1.2.2)
//
// An error will be logged and a nil IssuerSerial returned if no certificate is present or if
// the certificate cannot be parsed..
func (c *Certificate) IssuerSerial() *set.IssuerSerial {
	cert, err := c.ParseCertificate()
	if err != nil {
		log.WithError(err).
			WithField("revocation", c).
			Warn("failed to parse the CCADB certificate when constructing a Issuer:Serial pair")
		return nil
	}
	issuer := cert.Issuer.ToRDNSequence()
	utils.Normalize(&issuer)
	is := set.NewIssuerSerial(&issuer, cert.SerialNumber.Bytes())
	return &is
}

// SubjectKeyHash parses the X.509 certificate retrieved from the CCADB,
// extracts the subject (https://tools.ietf.org/html/rfc5280#section-4.1.2.6) and
// SPKI (https://tools.ietf.org/html/rfc5280#section-4.1.2.7). The SPKI is hashed
// with SHA256.
//
// An error will be logged and a nil SubjectKeyHash returned if no certificate is present or if
// the certificate cannot be parsed..
func (c *Certificate) SubjectKeyHash() *set.SubjectKeyHash {
	cert, err := c.ParseCertificate()
	if err != nil {
		log.WithError(err).
			WithField("revocation", c).
			Warn("failed to parse the CCADB certificate when constructing a Subject:KeyHash pair")
		return nil
	}
	subject := cert.Subject.ToRDNSequence()
	utils.Normalize(&subject)
	hasher := sha256.New()
	hasher.Write(cert.RawSubjectPublicKeyInfo)
	hash := hasher.Sum(nil)
	skh := set.NewSubjectKeyHash(&subject, hash)
	return &skh
}

// ParseCertificate returns the parsed x509.Certificate.
//
// A nil certificate and an error is returned if the CCADB does not
// have a certificate, the certificate cannot be PEM decoded, or
// the certificate cannot be x509 decoded.
func (c *Certificate) ParseCertificate() (*x509.Certificate, error) {
	p := c.PEM()
	if p == "" {
		return nil, errors.New("CCADB record has an empty certificate field")
	}
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, fmt.Errorf("fail to decode pem from CCADB: '%s'", c.PemInfo)
	}
	return x509.ParseCertificate(b.Bytes)
}

// PEM returns a parseable PEM string from the PemInfo field.
// If you want to do something with the certificate then you should use
// this method rather than accessing the raw PemInfo field as the CCADB has
// as the habit of double encoding strings with inner single quotes.
func (c *Certificate) PEM() string {
	return strings.TrimSpace(strings.Trim(c.PemInfo, "'"))
}

// Since the CCADB has the physical certificate, we can represent ourselves as
// either an IssuerSerial OR a SubjectKeyHash.
func (c *Certificate) Type() set.Type {
	return set.Either
}
