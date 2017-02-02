package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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

func getRevocationsTxt(filename string, separate bool, upper bool) error {
	var (
		issuer string
		serial string
		err error
	)
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var dn = ""
	for scanner.Scan() {
		// process line
		line := scanner.Text()
		// Ignore comments
		if 0 == strings.Index(line, "#") {
			continue
		}
		if 0 == strings.Index(line, " ") {
			if len(dn) == 0 {
				log.Fatal("A serial number with no issuer is not valid. Exiting.")
			}
			issuer, err = oneCRL.DNToRFC4514(dn)
			if nil != err {
				log.Print(err)
			}
			
			serial, err = oneCRL.SerialToString(strings.Trim(line, " "), separate, upper)
			if nil != err {
				log.Print(err)
			}
			fmt.Printf("\"%s\",\"%s\"\n", issuer, serial);
			continue
		}
		if 0 == strings.Index(line, "\t") {
			log.Fatal("revocations.txt containing subject / pubkey pairs not yet supported");
			log.Fatal("A public key hash with no subject is not valid. Exiting.")
		}
		dn = line
	}
	
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return nil;
}

func main() {
	urlPtr := flag.String("url", "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records", "The URL of the blocklist record data")
	filePtr := flag.String("file", "", "revocations.txt to load entries from");
	upper := flag.Bool("upper", false, "Should hex values be upper case?")
	separate := flag.Bool("separate", false, "Should the serial number bytes be colon separated?")
	flag.Parse()
	res := new(Results)
	// If no file is specified, fall back to loading from an URL
	if len(*filePtr) == 0 {
		getJSON(*urlPtr, res)
	} else {
		getRevocationsTxt(*filePtr, *separate, *upper)
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
