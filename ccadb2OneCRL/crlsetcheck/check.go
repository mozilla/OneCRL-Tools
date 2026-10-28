/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crlsetcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/crlset"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/set"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"
)

type Kind string

const (
	// The CCADB records the certificate as revoked, but it is not in OneCRL.
	NotInOneCRL Kind = "not-in-onecrl"
	// The certificate is a child of an included root, but it is not in the CCADB.
	Undisclosed Kind = "undisclosed"
	// The CCADB does not record the certificate as revoked.
	CCADBNotRevoked Kind = "ccadb-not-revoked"
)

func (k Kind) Description() string {
	switch k {
	case NotInOneCRL:
		return "revoked intermediate is missing from OneCRL"
	case Undisclosed:
		return "revoked certificate issued by an included root is not disclosed in the CCADB"
	case CCADBNotRevoked:
		return "revoked intermediate is not marked as revoked in the CCADB"
	}
	return string(k)
}

type Finding struct {
	Kind Kind
	// Hex encoded SHA-256 hash of the issuer's SubjectPublicKeyInfo.
	IssuerSPKIHash string
	// Hex encoded serial number without leading zero bytes.
	Serial string
	// Distinguished name of the issuer.
	Issuer string
	// The remaining fields are only available when the CCADB has a copy of the certificate.
	Subject        string
	Fingerprint    string
	CAOwner        string
	RevocationDate string
	ReasonCode     string
	OneCRLStatus   string
}

// Key uniquely identifies a finding across runs.
func (f *Finding) Key() string {
	if f.Fingerprint != "" {
		return fmt.Sprintf("%s:%s", f.Kind, f.Fingerprint)
	}
	return fmt.Sprintf("%s:%s:%s", f.Kind, f.IssuerSPKIHash, f.Serial)
}

type Input struct {
	CRLSet *crlset.CRLSet
	// Certificates of included roots that are trusted for websites.
	Roots []*x509.Certificate
	// Intermediate certificates in the CCADB that are not revoked.
	Intermediates []*x509.Certificate
	// Intermediate certificates in the CCADB that are revoked.
	Revoked []*ccadb.Certificate
	OneCRL  []*onecrl.Record
}

type issuer struct {
	subject []byte
	isRoot  bool
}

type child struct {
	cert    *x509.Certificate
	revoked *ccadb.Certificate // nil if the CCADB does not record the certificate as revoked
}

// Check finds revoked CA certificates in Chrome's CRLSet that are missing
// from OneCRL, and uses the CCADB to explain why.
//
// The CRLSet identifies a revoked certificate by its issuer's SPKI hash and
// its serial number. OneCRL identifies a revoked certificate by its issuer's
// distinguished name and its serial number (or by its subject and SPKI hash).
// We use the certificates in the CCADB to bridge the two.
func Check(in *Input) []*Finding {
	issuers := make(map[[32]byte][]issuer)
	addIssuer := func(cert *x509.Certificate, isRoot bool) {
		hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		for i, existing := range issuers[hash] {
			if string(existing.subject) == string(cert.RawSubject) {
				issuers[hash][i].isRoot = existing.isRoot || isRoot
				return
			}
		}
		issuers[hash] = append(issuers[hash], issuer{subject: cert.RawSubject, isRoot: isRoot})
	}
	children := make(map[set.IssuerSerial]child)
	addChild := func(cert *x509.Certificate, revoked *ccadb.Certificate) {
		serial, err := utils.RawSerialBytes(cert.RawTBSCertificate)
		if err != nil {
			log.WithError(err).WithField("subject", utils.NameString(cert.RawSubject)).Warn("failed to extract serial number")
			return
		}
		key := set.NewIssuerSerial(cert.RawIssuer, crlset.NormalizeSerial(serial))
		if existing, ok := children[key]; ok && existing.revoked != nil {
			return
		}
		children[key] = child{cert: cert, revoked: revoked}
	}
	for _, root := range in.Roots {
		addIssuer(root, true)
	}
	for _, cert := range in.Intermediates {
		addIssuer(cert, false)
		addChild(cert, nil)
	}
	missing := 0
	for _, record := range in.Revoked {
		cert, err := record.ParseCertificate()
		if errors.Is(err, ccadb.ErrNoCertificate) {
			missing++
			log.WithField("fingerprint", record.Fingerprint).Debug("revoked CCADB record has no certificate")
			continue
		}
		if err != nil {
			log.WithError(err).WithField("fingerprint", record.Fingerprint).Warn("failed to parse revoked CCADB certificate")
			continue
		}
		addIssuer(cert, false)
		addChild(cert, record)
	}
	if missing > 0 {
		log.WithField("count", missing).Info("skipped revoked CCADB records that have no certificate")
	}

	inOneCRL := make(map[string]bool)
	for _, record := range in.OneCRL {
		switch record.Type() {
		case set.IssuerSerialType:
			issuer, err := utils.B64Decode(record.IssuerName)
			if err != nil {
				log.WithError(err).WithField("record", record).Warn("failed to decode OneCRL issuer")
				continue
			}
			serial, err := utils.B64Decode(record.SerialNumber)
			if err != nil {
				log.WithError(err).WithField("record", record).Warn("failed to decode OneCRL serial")
				continue
			}
			inOneCRL[string(set.NewIssuerSerial(issuer, crlset.NormalizeSerial(serial)))] = true
		case set.SubjectKeyHashType:
			if subjectKeyHash := record.SubjectKeyHash(); subjectKeyHash != nil {
				inOneCRL[string(*subjectKeyHash)] = true
			}
		}
	}

	findings := make([]*Finding, 0)
	for parentHash, serials := range in.CRLSet.Entries {
		for _, issuer := range issuers[parentHash] {
			for _, serial := range serials {
				if f := classify(issuer, parentHash, serial, children, inOneCRL); f != nil {
					findings = append(findings, f)
				}
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Key() < findings[j].Key() })
	return findings
}

func classify(issuer issuer, parentHash [32]byte, serial []byte, children map[set.IssuerSerial]child, inOneCRL map[string]bool) *Finding {
	key := set.NewIssuerSerial(issuer.subject, serial)
	if inOneCRL[string(key)] {
		return nil
	}
	finding := &Finding{
		IssuerSPKIHash: hex.EncodeToString(parentHash[:]),
		Serial:         hex.EncodeToString(serial),
		Issuer:         utils.NameString(issuer.subject),
	}
	c, ok := children[key]
	if !ok {
		// Revocations of certificates issued by intermediates are almost all
		// end-entity certificates, which are out of scope for OneCRL.
		if !issuer.isRoot {
			return nil
		}
		finding.Kind = Undisclosed
		return finding
	}
	spkiHash := sha256.Sum256(c.cert.RawSubjectPublicKeyInfo)
	if inOneCRL[string(set.NewSubjectKeyHash(c.cert.RawSubject, spkiHash[:]))] {
		return nil
	}
	if !tlsCapable(c.cert) {
		return nil
	}
	fingerprint := sha256.Sum256(c.cert.Raw)
	finding.Subject = utils.NameString(c.cert.RawSubject)
	finding.Fingerprint = hex.EncodeToString(fingerprint[:])
	if c.revoked == nil {
		finding.Kind = CCADBNotRevoked
		return finding
	}
	finding.Kind = NotInOneCRL
	finding.CAOwner = c.revoked.CAOwner
	finding.RevocationDate = c.revoked.DateOfRevocation
	finding.ReasonCode = c.revoked.ReasonCode
	finding.OneCRLStatus = c.revoked.OneCRLStatus
	// Mozilla has explicitly decided that these do not belong in OneCRL.
	if c.revoked.OneCRLStatus == "Not Applicable" {
		return nil
	}
	return finding
}

// A certificate can issue TLS server certificates unless it has an EKU
// extension that excludes both serverAuth and anyExtendedKeyUsage.
func tlsCapable(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
