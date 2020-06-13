/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package onecrl

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/common"
	log "github.com/sirupsen/logrus"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"

	"github.com/pkg/errors"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"

	"github.com/mozilla/OneCRL-Tools/kinto/api"
	"github.com/mozilla/OneCRL-Tools/kinto/api/buckets"
	"github.com/mozilla/OneCRL-Tools/kinto/api/collections"
)

func NewOneCRL() *OneCRL {
	return &OneCRL{
		Collection: collections.NewCollection(buckets.NewBucket("security-state"), "onecrl"),
		Data:       []*Record{},
	}
}

type OneCRL struct {
	*collections.Collection `json:"-"`
	Data                    []*Record `json:"data"`
}

type Record struct {
	// It is rather awkward to hold onto a pointer to the associated CCADB entry,
	// however it makes constructing a Comparison struct much easier in main
	// as you can bundle the two together as soon has you find the match.
	// However, this could be a good opportunity for refactoring/decoupling.
	CCADB        *ccadb.Certificate `json:"-"`
	Schema       int                `json:"schema"`
	Details      Details            `json:"details"`
	Enabled      bool               `json:"enabled"`
	IssuerName   string             `json:"issuerName,omitempty"`
	SerialNumber string             `json:"serialNumber,omitempty"`
	Subject      string             `json:"subject,omitempty"`
	PubKeyHash   string             `json:"pubKeyHash,omitempty"`
	*api.Record
}

type Details struct {
	Bug     string `json:"bug"`
	Who     string `json:"who"`
	Why     string `json:"why"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

func (r *Record) Type() common.Type {
	if r.PubKeyHash != "" && r.Subject != "" {
		return common.SubjectKeyHashType
	} else if r.IssuerName != "" && r.SerialNumber != "" {
		return common.IssuerSerialType
	}
	log.WithField("entry", r).Panic("a OneCRL entry was found that does not appear to be either a " +
		"SubjectPubKeyHash type nor the more common IssuerSerial type")
	// The Go compiler understands that the above statement panics the program and compiles just fine, but Goland
	// will complain endlessly (as of Aug 2020) that this method will not compile due to a missing return.
	return common.IssuerSerialType
}

// IssuerSerial parses the X.509 certificate retrieved from the CCADB,
// extracts the issuer (https://tools.ietf.org/html/rfc5280#section-4.1.2.4) and
// serial number (https://tools.ietf.org/html/rfc5280#section-4.1.2.2)
//
// An error will be logged and a nil IssuerSerial will be returned if the issuer field could not be
// parsed or the serial number could not be b64 decoded.
func (r *Record) IssuerSerial() *common.IssuerSerial {
	issuer, err := r.parseIssuer()
	if err != nil {
		log.WithError(err).
			WithField("record", r).
			Warn("failed to parse an issuer field from OneCRL")
		return nil
	}
	utils.Normalize(issuer)
	// Decoding and re-encoding the string coerces everyone to the same b64 standard.
	// That is, those without padding get forced into having padding.
	serial, err := utils.B64Decode(r.SerialNumber)
	if err != nil {
		log.WithError(err).
			WithField("record", r).
			Warn("OneCRL serial base64 serial decode error")
		return nil
	}
	is := common.NewIssuerSerial(issuer, serial)
	return &is
}

// SubjectKeyHash parses the subject (https://tools.ietf.org/html/rfc5280#section-4.1.2.6)
// field of a OneCRL entry.
//
// An error will be logged and a nil SubjectKeyHash will be returned if the subject field could not be
// parsed or the public key hash could not be b64 decoded.
func (r *Record) SubjectKeyHash() *common.SubjectKeyHash {
	subject, err := r.parseSubject()
	if err != nil {
		log.WithError(err).
			WithField("record", r).
			Warn("failed to parse an subject field from OneCRL")
		return nil
	}
	utils.Normalize(subject)
	// Decoding and re-encoding the string coerces everyone to the same b64 standard.
	// That is, those without padding get forced into having padding.
	hash, err := utils.B64Decode(r.PubKeyHash)
	if err != nil {
		log.WithError(err).
			WithField("record", r).
			Warn("OneCRL serial base64 key hash decode error")
		return nil
	}
	skh := common.NewSubjectKeyHash(subject, hash)
	return &skh
}

func (r *Record) parseSubject() (*pkix.RDNSequence, error) {
	if r.Type() != common.SubjectKeyHashType {
		return nil, fmt.Errorf("attempted to parse a subject from a non SubjectPubKeyHash onecrl entry, got %d", r.Type())
	}
	subject, err := parseRDNS(r.Subject)
	if err != nil {
		return nil, err
	}
	return subject, nil
}

func (r *Record) parseIssuer() (*pkix.RDNSequence, error) {
	if r.Type() != common.IssuerSerialType {
		return nil, fmt.Errorf("attempted to parse an issuer from a non IssuerSerial onecrl entry, got %d", r.Type())
	}
	issuer, err := parseRDNS(r.IssuerName)
	if err != nil {
		return nil, err
	}
	return issuer, nil
}

// A Comparison holds the same piece of information in the preferred
// representation of OneCRL and CCADB. The purpose is to facilitate
// quick left/right comparisons between the datasets.
//
// E.G. OneCRL encodes a serial number as a base64 however the CCADB
// encodes it as an uppercase hexadecimal.
type Comparison struct {
	OneCRL string
	CCADB  string
}

type IssuerSerialComparison struct {
	Issuer Comparison `json:"issuer"`
	Serial Comparison `json:"serial"`
}

type SubjectKeyHashComparison struct {
	Subject Comparison `json:"subject"`
	Keyhash Comparison `json:"keyHash"`
}

// ToComparison generates a comparison between OneCRL and
// CCADB that easy for a human to read in a left/right
// sort of way.
//
// Example object may be:
//
//	{
//		"issuer": {
//			"OneCRL": "MFAxJDAiBgNVBAsTG0dsb2JhbFNpZ24gRUNDIFJvb3QgQ0EgLSBSNTETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbg==",
//			"CCADB": "GlobalSign"
//		},
//		"serial": {
//			"OneCRL": "Ae5fInnr9AhpWVIjkw==",
//			"CCADB": "01EE5F2279EBF4086959522393"
//		}
//	}
func (r *Record) ToComparison() (interface{}, error) {
	switch r.Type() {
	case common.IssuerSerialType:
		return IssuerSerialComparison{
			Issuer: Comparison{
				OneCRL: r.IssuerName,
				CCADB:  r.CCADB.CertificateIssuerName,
			},
			Serial: Comparison{
				OneCRL: r.SerialNumber,
				CCADB:  r.CCADB.CertificateSerialNumber,
			},
		}, nil
	case common.SubjectKeyHashType:
		raw, err := utils.B64Decode(r.PubKeyHash)
		if err != nil {
			return nil, err
		}
		return SubjectKeyHashComparison{
			Subject: Comparison{
				OneCRL: r.Subject,
				CCADB:  r.CCADB.CertificateSubjectCommonName,
			},
			Keyhash: Comparison{
				OneCRL: r.PubKeyHash,
				CCADB:  fmt.Sprintf("%X", raw),
			},
		}, nil
	default:
		log.Panic("non-exhaustive switch")
		return nil, nil
	}
}

// FromCCADB constructs a new OneCRL Record from the provided
// CCADB certificate.
//
// The outcome of this procedure ultimately is what becomes
// the proposed changed to OneCRL.
func FromCCADB(c *ccadb.Certificate) (*Record, error) {
	cert, err := c.ParseCertificate()
	if err != nil {
		return nil, err
	}
	record := &Record{
		CCADB: c,
		Details: Details{
			Bug:     "",
			Who:     "",
			Why:     "",
			Name:    "",
			Created: "",
		},
		Enabled:      false,
		IssuerName:   utils.B64Encode(cert.RawIssuer),
		SerialNumber: utils.B64Encode(cert.SerialNumber.Bytes()),
		Subject:      "",
		PubKeyHash:   "",
	}
	return record, nil
}

func parseRDNS(rdns string) (*pkix.RDNSequence, error) {
	i, err := utils.B64Decode(rdns)
	if err != nil {
		return nil, errors.Wrap(err, "OneCRL RDNS b64 decode error")
	}
	r := &pkix.RDNSequence{}
	_, err = asn1.Unmarshal(i, r)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("OneCRL RDNS asn1 decode error for '%s'", rdns))
	}
	return r, nil
}
