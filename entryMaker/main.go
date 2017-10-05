package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
	"io/ioutil"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	certPtr := flag.String("cert", "", "a certificate file")
	revocationTypePtr := flag.String("type", "issuer-serial", "What type of revocation you want (options: issuer-serial, subject-pubkey)")
	flag.Parse()

	var certData []byte
	if nil != certPtr && len(*certPtr) > 0 {
		// Get the cert from the args
		var err error
		certData, err = ioutil.ReadFile(*certPtr)
		check(err)
	}

	if len(certData) > 0 {
		// Maybe it's PEM; try to parse as PEM, if that fails, just use the bytes
		// We only care about the first block for now
		block, _ := pem.Decode(certData)
		if nil == block {
			panic(errors.New("There was a problem decoding the certificate"))
		}
		certData = block.Bytes

		cert, err := x509.ParseCertificate(certData)
		check(err)

		var record oneCRL.Record
		switch *revocationTypePtr {
		case "issuer-serial":
			issuerString := base64.StdEncoding.EncodeToString(cert.RawIssuer)

			if marshalled, err := asn1.Marshal(cert.SerialNumber); err == nil {
				serialString := base64.StdEncoding.EncodeToString(marshalled[2:])
				record = oneCRL.Record{IssuerName: issuerString, SerialNumber: serialString}
			}

		case "subject-pubkey":
			subjectString := base64.StdEncoding.EncodeToString(cert.RawSubject)

			if pubKeyData, err := x509.MarshalPKIXPublicKey(cert.PublicKey); err == nil {
				hash := sha256.Sum256(pubKeyData)
				base64EncodedHash := base64.StdEncoding.EncodeToString(hash[:])
				record = oneCRL.Record{Subject: subjectString, PubKeyHash: base64EncodedHash}
			}
		default:
		}

		if recordJson, err := json.MarshalIndent(record, "  ", "  "); nil == err {
			fmt.Printf("%s\n", recordJson)
		} else {
			panic(err)
		}
	}
}
