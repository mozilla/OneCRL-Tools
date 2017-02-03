package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"github.com/mozmark/OneCRL-Tools/oneCRL"	
)

func getJSON(url string, target interface{}) error {
	r, err := http.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(target)
}

type Results struct {
	Data []struct {
		IssuerName   string
		SerialNumber string
	}
}

type OneCRLPrinter struct {
	separate bool
	upper bool
}

func (p OneCRLPrinter) LoadRecord(record oneCRL.Record) {
	var (
		issuer string
		serial string
		err error
	)
	issuer, err = oneCRL.DNToRFC4514(record.IssuerName)
	if nil != err {
		log.Print(err)
	}

	serial, err = oneCRL.SerialToString(record.SerialNumber, p.separate, p.upper)
	if nil != err {
		log.Print(err)
	}	
	fmt.Printf("\"%s\",\"%s\"\n", issuer, serial);
}


func main() {
	urlPtr := flag.String("url", "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records", "The URL of the blocklist record data")
	filePtr := flag.String("file", "", "revocations.txt to load entries from");
	upper := flag.Bool("upper", false, "Should hex values be upper case?")
	separate := flag.Bool("separate", false, "Should the serial number bytes be colon separated?")
	flag.Parse()
	res := new(Results)
	printer := OneCRLPrinter{separate:*separate, upper:*upper}
	// If no file is specified, fall back to loading from an URL
	if len(*filePtr) == 0 {
		getJSON(*urlPtr, res)
	} else {
		oneCRL.LoadRevocationsTxt(*filePtr, printer)
	}
	for idx := range res.Data {
		IssuerName := res.Data[idx].IssuerName
		SerialNumber := res.Data[idx].SerialNumber
		hexSerial, err2 := oneCRL.SerialToString(SerialNumber, *separate, *upper)
		if nil != err2 {
			log.Print(err2)
		}
		decodedIssuer, err3 := oneCRL.DNToRFC4514(IssuerName)
		if err3 != nil {
			log.Print(err3)
		}
		fmt.Printf("\"%s\",\"%s\", \"%s\"\n", decodedIssuer, hexSerial, IssuerName)
	}
}
