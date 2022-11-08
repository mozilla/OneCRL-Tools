/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
	"github.com/mozilla/OneCRL-Tools/util"
	"io/ioutil"
	"time"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// certificate-transparency-go/x509 is too strict for our purposes.
// re-purpose it to be less strict.
type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString  `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString  `asn1:"optional,tag:2"`
	Extensions         []asn1.RawValue `asn1:"optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func parseCertificate(asn1Data []byte) (*certificate, error) {
	var cert certificate
	rest, err := asn1.UnmarshalWithParams(asn1Data, &cert, "lax")
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	return &cert, nil
}

func main() {
	certPtr := flag.String("cert", "", "a DER or PEM encoded certificate file")
	exceptionsPtr := flag.String("exceptions", "", "A JSON document containing exceptional additions")
	revocationTypePtr := flag.String("type", "issuer-serial", "What type of revocation you want (options: issuer-serial, subject-pubkey)")
	checkValidityPtr := flag.String("checkvalidity", "no", "should validity be checked? (yes / no)")

	whoPtr := flag.String("who", "", "email of revoking party")
	whyPtr := flag.String("why", "", "reason for revocation")
	namePtr := flag.String("name", "", "name of this revocation")
	bugPtr := flag.String("bug", "", "bug URL for this revocation")
	overwritePtr := flag.Bool("overwrite", false, "Overwrite the exceptions file?")

	flag.Parse()

	// Optionally load the exceptions list to make the addition to
	exceptionsList := new(oneCRL.Records)
	if len(*exceptionsPtr) != 0 {
		if err := util.LoadExceptions(*exceptionsPtr, &oneCRL.Records{}, exceptionsList); nil != err {
			panic(err)
		}
	}

	var certData []byte
	if nil != certPtr && len(*certPtr) > 0 {
		// Get the cert from the args
		var err error
		certData, err = ioutil.ReadFile(*certPtr)
		check(err)
	}

	var record oneCRL.Record
	if len(certData) > 0 {
		// Maybe it's PEM; try to parse as PEM, if that fails, just use the bytes
		// We only care about the first block for now
		block, _ := pem.Decode(certData)
		if nil == block {
			panic(errors.New("There was a problem decoding the certificate"))
		}
		certData = block.Bytes

		cert, err := parseCertificate(certData)
		check(err)

		// Check to see if the cert is still valid (if it's not, we don't want
		// an entry
		if "yes" == *checkValidityPtr {
			if time.Now().After(cert.TBSCertificate.Validity.NotAfter) {
				panic(errors.New(fmt.Sprintf("Cert is no longer valid (NotAfter %v)", cert.TBSCertificate.Validity.NotAfter)))
			}
		}

		switch *revocationTypePtr {
		case "issuer-serial":
			issuerString := base64.StdEncoding.EncodeToString(cert.TBSCertificate.Issuer.FullBytes)
			serialString := base64.StdEncoding.EncodeToString(cert.TBSCertificate.SerialNumber.Bytes)
			record = oneCRL.Record{IssuerName: issuerString, SerialNumber: serialString}

		case "subject-pubkey":
			subjectString := base64.StdEncoding.EncodeToString(cert.TBSCertificate.Subject.FullBytes)

			if pubKeyData, err := x509.MarshalPKIXPublicKey(cert.TBSCertificate.PublicKey); err == nil {
				hash := sha256.Sum256(pubKeyData)
				base64EncodedHash := base64.StdEncoding.EncodeToString(hash[:])
				record = oneCRL.Record{Subject: subjectString, PubKeyHash: base64EncodedHash}
			}
		default:
			panic("Unexpected revocation type")
		}
	}

	// Set the values on the new record
	record.Enabled = true
	record.Details.Who = *whoPtr
	record.Details.Why = *whyPtr
	record.Details.Name = *namePtr
	record.Details.Bug = *bugPtr
	record.Details.Created = ""

	var toPrint interface{}

	if len(exceptionsList.Data) > 0 {
		exceptionsList.Data = append(exceptionsList.Data, record)
		toPrint = exceptionsList
	} else {
		toPrint = record
	}

	if *overwritePtr && len(exceptionsList.Data) > 0 {
		if err := util.StoreExceptions(*exceptionsPtr, exceptionsList); nil != err {
			panic(err)
		}
	} else {
		formattedJson, err := json.MarshalIndent(toPrint, "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", formattedJson)
	}
}
