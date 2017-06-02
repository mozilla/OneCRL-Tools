package main

import (
	"flag"
	"fmt"
	"github.com/mozmark/OneCRL-Tools/oneCRL"	
)

type revocations struct {
	byIssuerSerialNumber map[string][]string
	bySubjectPubKeyHash map[string][]string
}

func (r *revocations) LoadRecord(record oneCRL.Record) {
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

func main() {
	oneCRL.DefineFlags()
	flag.Parse()

	rev := new (revocations)
	
	config := oneCRL.Config
	url := config.GetRecordURL()

	err := oneCRL.LoadJSONFromURL(url, rev)
	if err != nil {
		panic(err)
	}

	for issuer, serials := range rev.byIssuerSerialNumber {
		fmt.Printf("%s\n", issuer)
		for _, serial := range serials {
			fmt.Printf(" %s\n", serial)
		}
	}
	for subject, pubKeyHashes := range rev.bySubjectPubKeyHash {
		fmt.Printf("%s\n", subject)
		for _, pubKeyHash := range pubKeyHashes {
			fmt.Printf("\t%s\n", pubKeyHash)
		}
	}
}
