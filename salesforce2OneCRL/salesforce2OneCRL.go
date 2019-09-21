/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	constraintsx509 "github.com/jcjones/constraintcrypto/x509"
	"github.com/mozilla/OneCRL-Tools/config"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
	"github.com/mozilla/OneCRL-Tools/salesforce"
	"github.com/mozilla/OneCRL-Tools/util"
)

const DEFAULT_EXCEPTIONS string = "exceptions.json"

func main() {
	exceptionsLocation := ""

	filePtr := flag.String("file", "", "The file to read data from")
	flag.StringVar(&exceptionsLocation, "exceptions", DEFAULT_EXCEPTIONS, "A JSON document containing exceptional additions")
	urlPtr := flag.String("url", "https://ccadb-public.secure.force.com/mozilla/PublicInterCertsReadyToAddToOneCRLPEMCSV", "the URL of the salesforce data")
	bugPtr := flag.String("bug", "", "the URL of the bug relating to this change")
	whoPtr := flag.String("who", "", "who made this change")
	whyPtr := flag.String("why", "", "why is this change happening")

	config.DefineFlags()

	flag.Parse()

	conf := config.GetConfig()

	// If default, try to fetch exceptions location from config or environment
	if DEFAULT_EXCEPTIONS == exceptionsLocation {
		envExceptions, confPresent := conf.AdditionalConfig["exceptions"]
		if confPresent {
			exceptionsLocation = envExceptions
		} else {
			newLocation, envPresent := os.LookupEnv("exceptions")
			if envPresent {
				exceptionsLocation = newLocation
			}
		}
	}

	var stream io.ReadCloser

	comment := ""

	// make a slice of additions
	additions := new(oneCRL.Records)

	if "" != *filePtr {
		fmt.Printf("loading salesforce data from %s\n", *filePtr)
		// get the stream from a file
		csvfile, err := os.Open(*filePtr)
		if err != nil {
			fmt.Printf("problem loading salesforce data from file %s\n", err)
			return
		}

		stream = io.ReadCloser(csvfile)
	} else {
		fmt.Printf("loading salesforce data from %s\n", *urlPtr)

		// get the stream from URL
		r, err := http.Get(*urlPtr)
		if err != nil {
			fmt.Printf("problem fetching salesforce data from URL %s\n", err)
			return
		}
		defer r.Body.Close()

		stream = r.Body
	}

	///*
	existing, err := oneCRL.FetchExistingRevocations(conf.KintoCollectionURL + "/records")
	if nil != err {
		fmt.Printf("%s\n", err)
	}

	if len(exceptionsLocation) != 0 {
		if err := util.LoadExceptions(exceptionsLocation, existing, additions); nil != err {
			panic(err)
		}
	}
	//*/

	row := 1
	revoked := salesforce.FetchRevokedCertInfo(stream)

	for _, each := range revoked {
		row++

		if each.Status == "Ready to Add" {
			certData, err := salesforce.CertDataFromSalesforcePEM(each.PEM)
			if err != nil {
				fmt.Printf("(%d, %s, %s) can't decode PEM %s\n", row, each.CSN, each.CertName, each.PEM)
			}

			cert, err := constraintsx509.ParseCertificate(certData)
			if err != nil {
				fmt.Printf("(%d, %s, %s) could not parse cert\n", row, each.CSN, each.CertName)
				continue
			}

			issuerString := base64.StdEncoding.EncodeToString(cert.RawIssuer)
			serialBytes, err := asn1.Marshal(cert.SerialNumber)

			if err != nil {
				fmt.Printf("(%d, %s, %s) could not marshal serial number\n", row, each.CSN, each.CertName)
				continue
			}

			serialString := base64.StdEncoding.EncodeToString(serialBytes[2:])

			record := oneCRL.Record{IssuerName: issuerString, SerialNumber: serialString}
			if util.RecordExists(record, existing) {
				fmt.Printf("(%d, %s, %s) revocation already in OneCRL\n", row, each.CSN, each.CertName)
				continue
			}

			matchFound := false
			lineErrors := ""
			lineWarnings := ""
			for _, CRLLocation := range each.CRLs {
				if 0 != strings.Index(strings.Trim(CRLLocation, " "), "http") {
					if len(strings.Trim(CRLLocation, " ")) > 0 {
						lineErrors += fmt.Sprintf("Ignoring CRL at %s because it doesn't look like an HTTP url\n", CRLLocation)
					}
					continue
				}

				// fetch and parse the CRL
				res, err := http.Get(CRLLocation)
				if err != nil {
					lineErrors += fmt.Sprintf("There was a problem fetching the CRL from %s\n", CRLLocation)
					continue
				}

				buf := new(bytes.Buffer)
				_, err = buf.ReadFrom(res.Body)
				if err != nil {
					fmt.Printf("Problem reading the CRL data at %s\n", CRLLocation)
					continue
				}
				crlData := buf.Bytes()

				// Maybe the CRL is PEM - try to parse as PEM and just use the raw
				// data if that fails
				pemBlock, _ := pem.Decode(crlData)
				if pemBlock != nil {
					crlData = pemBlock.Bytes
				}

				crl, err := constraintsx509.ParseCRL(crlData)
				if err != nil {
					lineErrors += fmt.Sprintf("Could not parse the CRL at \"%s\" %v\n",
						CRLLocation, err)
					continue
				}

				// check the CRL is still current
				if crl.HasExpired(time.Now()) {
					lineErrors += fmt.Sprintf("crl %s has expired\n", CRLLocation)
					continue
				}

				// Check the cert issuer and the CRL issuer match
				crlIssuerBytes, err := asn1.Marshal(crl.TBSCertList.Issuer)
				if nil != err {
					lineErrors += fmt.Sprintf("could not marshal CRL issuer %s\n", CRLLocation)
				}

				readibleCertIssuer, err := oneCRL.DNToRFC4514(issuerString)
				if nil != err {
					lineErrors += fmt.Sprintf("could not make readible issuer %s\n", CRLLocation)
					continue
				}

				if !(oneCRL.ByteArrayEquals(cert.RawIssuer, crlIssuerBytes)) {
					if !oneCRL.NamesDataMatches(cert.RawIssuer, crlIssuerBytes) {
						lineErrors += fmt.Sprintf("CRL issuer from CRL at %s does not match issuer\n%s !=\n%s\nCRL issuer:  %s\nCert issuer: %s\n", CRLLocation,
							hex.EncodeToString(crlIssuerBytes),
							hex.EncodeToString(cert.RawIssuer),
							oneCRL.RFC4514ish(crl.TBSCertList.Issuer),
							readibleCertIssuer)
						continue
					} else {
						lineWarnings += fmt.Sprintf("Warning: CRL issuer from CRL at %s does not match issuer\n%s !=\n%s\nCRL issuer:  %s\nCert issuer: %s\n", CRLLocation,
							hex.EncodeToString(crlIssuerBytes),
							hex.EncodeToString(cert.RawIssuer),
							oneCRL.RFC4514ish(crl.TBSCertList.Issuer),
							readibleCertIssuer)
					}
				}

				for revoked := range crl.TBSCertList.RevokedCertificates {
					certEntry := crl.TBSCertList.RevokedCertificates[revoked]
					serialBytesFromCRL, _ := asn1.Marshal(certEntry.SerialNumber)
					if oneCRL.ByteArrayEquals(serialBytes, serialBytesFromCRL) {
						matchFound = true
					}
				}
			}
			if !matchFound {
				if lineErrors == "" {
					lineErrors = "\n"
				}
				errorLine := fmt.Sprintf("(%d, %s, %s) no match found in CRL: %s\n", row, each.CSN, each.CertName, lineErrors)
				fmt.Printf(errorLine)
				comment = comment + errorLine
				if "yes" == conf.EnforceCRLChecks {
					continue
				}
			}

			if len(lineWarnings) != 0 {
				fmt.Printf(lineWarnings)
			}

			// record the entry for output later
			rec := oneCRL.Record{}
			rec.IssuerName = issuerString
			rec.SerialNumber = serialString
			rec.Details.Bug = *bugPtr
			rec.Details.Who = *whoPtr
			rec.Details.Why = *whyPtr
			rec.Enabled = true
			additions.Data = append(additions.Data, rec)
		}
	}

	for _, addition := range additions.Data {
		fmt.Printf("Mocking addition of entry to OneCRL.\n")
		fmt.Printf("%s\n", addition)

		err = oneCRL.AddEntries(additions, existing, true, comment)
		if nil != err {
			panic(err)
		}

		fmt.Printf("salesforce2OneCRL: Only adding one entry. Exiting..\n")
		os.Exit(0)
	}

	/*
	err = oneCRL.AddEntries(additions, existing, true, comment)
	if nil != err {
		panic(err)
	}
	*/
}
