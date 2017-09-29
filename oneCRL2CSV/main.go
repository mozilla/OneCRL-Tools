package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"github.com/mozilla/OneCRL-Tools/config"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
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
	fmt.Printf("\"%s\",\"%s\"\n", issuer, serial)
}


func main() {
	// TODO: add flag for custom endpoint (e.g. local kinto)
	filePtr := flag.String("file", "", "revocations.txt to load entries from")
	fileFormatPtr := flag.String("format", "revocations.txt", "the format to load data in (options: revocations.txt, bug)")
	upper := flag.Bool("upper", false, "Should hex values be upper case?")
	separate := flag.Bool("separate", false, "Should the serial number bytes be colon separated?")
	config.DefineFlags()
	flag.Parse()

	printer := OneCRLPrinter{separate:*separate, upper:*upper}

	config := config.GetConfig()

	// If no file is specified, fall back to loading from an URL
	if len(*filePtr) == 0 {
		err, url := config.GetRecordURL()
		if nil == err {
			oneCRL.LoadJSONFromURL(url, printer)
		} else {
			panic(err)
		}
	} else {
		if "revocations.txt" == *fileFormatPtr {
			oneCRL.LoadRevocationsTxtFromFile(*filePtr, printer)
		} else if "bug" == *fileFormatPtr {
			oneCRL.LoadRevocationsFromBug(*filePtr, printer)
		} else {
			panic(errors.New("Unknown file format"))
		}
	}
}
