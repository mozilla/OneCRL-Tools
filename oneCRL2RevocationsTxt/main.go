package main

import (
	"flag"
	"fmt"
	"github.com/mozilla/OneCRL-Tools/oneCRL"	
	"github.com/mozilla/OneCRL-Tools/config"	
)

type RevocationsTxtData struct {
	byIssuerSerialNumber map[string][]string
	bySubjectPubKeyHash map[string][]string
}

func (r *RevocationsTxtData) LoadRecord(record oneCRL.Record) {
	// if there's no issuer name, assume we're revoking by Subject / PubKeyHash
	// otherwise it's issuer / serial
	if 0 == len(record.IssuerName) {
		if nil == r.bySubjectPubKeyHash {
			r.bySubjectPubKeyHash = make(map[string][]string)
		}
		if nil == r.bySubjectPubKeyHash[record.Subject]{
			pubKeyHashes := make([]string, 1)
			pubKeyHashes[0] = record.PubKeyHash
			r.bySubjectPubKeyHash[record.Subject] = pubKeyHashes
		} else {
			r.bySubjectPubKeyHash[record.Subject] = append(r.bySubjectPubKeyHash[record.Subject], record.PubKeyHash)
		}
	} else {
		if nil == r.byIssuerSerialNumber {
			r.byIssuerSerialNumber= make(map[string][]string)
		}
		if nil == r.byIssuerSerialNumber[record.IssuerName]{
			serials := make([]string, 1)
			serials[0] = record.SerialNumber
			r.byIssuerSerialNumber[record.IssuerName] = serials
		} else {
			r.byIssuerSerialNumber[record.IssuerName] = append(r.byIssuerSerialNumber[record.IssuerName], record.SerialNumber)
		}
	}
}

func (r *RevocationsTxtData) ToRevocationsTxtString() string {
	RevocationsTxtString := ""

	for issuer, serials := range r.byIssuerSerialNumber {
		RevocationsTxtString = RevocationsTxtString + fmt.Sprintf("%s\n", issuer)
		for _, serial := range serials {
			RevocationsTxtString = RevocationsTxtString + fmt.Sprintf(" %s\n", serial)
		}
	}
	for subject, pubKeyHashes := range r.bySubjectPubKeyHash {
		RevocationsTxtString = RevocationsTxtString +
			fmt.Sprintf("%s\n", subject)
		for _, pubKeyHash := range pubKeyHashes {
			RevocationsTxtString = RevocationsTxtString +
				fmt.Sprintf("\t%s\n", pubKeyHash)
		}
	}
	return RevocationsTxtString
}

func main() {
	config.DefineFlags()
	flag.Parse()

	rev := new (RevocationsTxtData)
	
	config := config.GetConfig()

	err, url := config.GetRecordURL()
	if err != nil {
		panic(err)
	}

	err = oneCRL.LoadJSONFromURL(url, rev)
	if err != nil {
		panic(err)
	}

	fmt.Printf(rev.ToRevocationsTxtString())
}
