package main

import (
	"bytes"
	constraintsx509  "github.com/jcjones/constraintcrypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"github.com/mozilla/OneCRL-Tools/config"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
	"os"
	"strings"
	"github.com/mozilla/OneCRL-Tools/salesforce"
	"time"
)

func getDataFromURL(url string) ([]byte, error) {
	r, _ := http.Get(url)
	defer r.Body.Close()

	return ioutil.ReadAll(r.Body)
}

func recordExists(item oneCRL.Record, records *oneCRL.Records) bool {
	for _, record := range records.Data {
		if item.EqualsRecord(record) {
			return true
		}
	}
	return false
}

func LoadExceptions(location string, existing *oneCRL.Records, records *oneCRL.Records) error {
	res := new(oneCRL.Records)
	var data []byte

	if 0 != strings.Index(strings.ToUpper(location), "HTTP") {
		// if it's not an HTTP URL, attempt to load from a file
		if fileData, err := ioutil.ReadFile(location); nil != err {
			fmt.Printf("problem loading oneCRL exceptions from file %s\n", err)
		} else {
			data = fileData
		}
	} else {
		// ensure it's not an HTTP location
		if 0 != strings.Index(strings.ToUpper(location), "HTTPS") {
			return errors.New("Cowardly refusing to load exceptions from a non HTTPS location")
		}
		if resp, err := http.Get(location); nil != err {
			return err;
		} else {
			defer resp.Body.Close()
			if urlData, err := ioutil.ReadAll(resp.Body); nil != err {
				return err;
			} else {
				data = urlData
			}
		}
	}

	if err := json.Unmarshal(data, res); nil != err {
		return err
	}

	for idx := range res.Data {
		record := res.Data[idx]
		if !recordExists(record, existing) {
			records.Data = append(records.Data, record)
		}
	}
	return nil
}

func main() {
	filePtr := flag.String("file", "", "The file to read data from")
	exceptionsPtr := flag.String("exceptions", "exceptions.json", "A JSON document containing exceptional additions")
	urlPtr := flag.String("url", "https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV", "the URL of the salesforce data")
	bugPtr := flag.String("bug", "", "the URL of the bug relating to this change")
	whoPtr := flag.String("who", "", "who made this change")
	whyPtr := flag.String("why", "", "why is this change happening")

	config.DefineFlags()

	flag.Parse()
	
	conf := config.GetConfig()

	var stream io.ReadCloser

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

	existing, err:= oneCRL.FetchExistingRevocations(conf.KintoCollectionURL + "/records")
	if nil != err{
		fmt.Printf("%s\n", err)
	}

	if len(*exceptionsPtr) != 0 {
		if err := LoadExceptions(*exceptionsPtr, existing, additions); nil != err {
			panic(err)
		}
	}
	
	row := 1
	revoked := salesforce.FetchRevokedCertInfo(stream)

	for _, each := range revoked {
		row++

		if each.Status == "Ready to Add" {
			certData, err:= salesforce.CertDataFromSalesforcePEM(each.PEM)
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
			if recordExists(record, existing) {
				fmt.Printf("(%d, %s, %s) revocation already in OneCRL\n", row, each.CSN, each.CertName)
				continue
			}


			matchFound := false
		    lineErrors := ""
			lineWarnings := ""
			for _, CRLLocation := range each.CRLs {
				if 0 != strings.Index(strings.Trim(CRLLocation, " "), "http") {
					if (len(strings.Trim(CRLLocation, " ")) > 0) {
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
					fmt.Println("Problem reading the CRL data at %s\n", CRLLocation)
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

				if ! (oneCRL.ByteArrayEquals(cert.RawIssuer, crlIssuerBytes)) {
					if ! oneCRL.NamesDataMatches(cert.RawIssuer, crlIssuerBytes) {
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
				fmt.Printf("(%d, %s, %s) no match found in CRL: %s", row, each.CSN, each.CertName, lineErrors)
				continue
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
	

	err = oneCRL.AddEntries(additions, existing, true)
	if nil != err {
		panic(err)
	}
}
