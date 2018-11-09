package main

import (
	"flag"
	"fmt"
	"github.com/mozilla/OneCRL-Tools/config"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
	"github.com/mozilla/OneCRL-Tools/salesforce"
	"strings"
)

type KintoUpdate struct {
	Data interface{} `json:"data"`
}

type IntermediateCertificateRecord struct {
	Id           string `json:"id,omitempty"`
	Subject      string `json:"subject"`
	PubKeyHash   string `json:"pubKeyHash"`
	Whitelist    bool   `json:"whitelist"`
	Details      struct {
		Who     string `json:"who"`
		Created string `json:"created"`
		Name    string `json:"name"`
		Why     string `json:"why"`
	} `json:"details"`
}

func main() {
	urlPtr := flag.String("url", "https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsWithPEMCSV", "the URL of the salesforce data")
	collectionPtr := flag.String("intermediateCollection", "https://kinto-writer.stage.mozaws.net/v1/buckets/security-state-staging/collections/intermediates", "the URL of the collection")

	config.DefineFlags()
	flag.Parse()

	intermediates, _ := salesforce.FetchPublicIntermediatesFrom(*urlPtr)
	for _, intermediate := range intermediates {
		// CertData: intermediate.PEM
		// TODO: calculate PudKeyHash, extract subject
		rec := IntermediateCertificateRecord{Whitelist: false}
		update := KintoUpdate{Data:rec}
		id := oneCRL.AddKintoObject(*collectionPtr, update)
		// fmt.Printf("PEM is %v\n", intermediate.PEM)
		attURL := fmt.Sprintf("%s/records/%s/attachment", *collectionPtr, id)
		fmt.Printf("Will POST attachment to %s\n", attURL)
		PEMReader := strings.NewReader(intermediate.PEM)
		oneCRL.AddKintoAttachment(attURL, PEMReader, "cert.png", false)
	}
}
