package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"github.com/mozmark/OneCRL-Tools/oneCRL"	
)

type OneCRLSet struct {
	records oneCRL.Records
}

func (set *OneCRLSet) LoadRecord(record oneCRL.Record) {
	set.records.Data = append(set.records.Data, record)
}

func (set *OneCRLSet) FetchData(location string) error {
	if 0 == strings.Index(strings.ToLower(location),"http://") ||
	   0 == strings.Index(strings.ToLower(location),"https://") {
	   return oneCRL.LoadJSONFromURL(location, set)
   } else if location == "production" {
	   return oneCRL.LoadJSONFromURL(oneCRL.ProductionPrefix + oneCRL.RecordsPath, set)
   } else if location == "stage" {
	   return oneCRL.LoadJSONFromURL(oneCRL.StagePrefix + oneCRL.RecordsPath, set)
   } else {
	   return oneCRL.LoadRevocationsTxtFromFile(location, set)
   }
}

func main() {
	set1 := new(OneCRLSet)
	set2 := new(OneCRLSet)

	oneCRL.DefineFlags()
	flag.Parse()
	
	config := oneCRL.Config

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("We need at least one OneCRL file to operate on")
		return
	}
	if len(args) > 2 {
		log.Fatal("oneCRL diff only operates on two OneCRL data sets")
		return
	}
	if len(args) < 2 {
		// TODO: Read env. options and (optionally) fetch data from a different
		// environment than production
		set1.FetchData(config.GetRecordURL())
		set2.FetchData(args[0])
	} else {
		set1.FetchData(args[0])
		set2.FetchData(args[1])
	}

	fmt.Printf("set1 has %d entries\n",len((*set1).records.Data))
	fmt.Printf("set2 has %d entries\n",len((*set2).records.Data))

	fmt.Println("Removals")
	changes := false
	for _, record := range set1.records.Data {
		found := false
		for _, record2 := range set2.records.Data {
			if record.EqualsRecord(record2) {
				found = true
			}
		}
		if !found {
			fmt.Printf("%s/n", oneCRL.StringFromRecord(record))
			changes = true
		}
	}
	if !changes {
		fmt.Println("(none)")
	}

	changes = false
	fmt.Println("Additions")
	for _, record := range set2.records.Data {
		found := false
		for _, record2 := range set1.records.Data {
			if record.EqualsRecord(record2) {
				found = true
			}
		}
		if !found {
			fmt.Printf("%s\n", oneCRL.StringFromRecord(record))
			changes = true
		}
	}
	if !changes {
		fmt.Println("(none)")
	}
}
