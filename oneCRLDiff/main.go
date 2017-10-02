/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"flag"
	"fmt"
	"github.com/mozilla/OneCRL-Tools/config"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
	"log"
	"strings"
)

type OneCRLSet struct {
	records oneCRL.Records
}

func (set *OneCRLSet) LoadRecord(record oneCRL.Record) {
	set.records.Data = append(set.records.Data, record)
}

func (set *OneCRLSet) FetchData(location string, config *config.OneCRLConfig) error {
	if 0 == strings.Index(strings.ToLower(location), "http://") ||
		0 == strings.Index(strings.ToLower(location), "https://") {
		return oneCRL.LoadJSONFromURL(location, set)
	} else {
		err, url := config.GetRecordURLForEnv(location)
		if nil == err {
			return oneCRL.LoadJSONFromURL(url, set)
		} else {
			return oneCRL.LoadRevocationsTxtFromFile(location, set)
		}
	}
}

func main() {
	set1 := new(OneCRLSet)
	set2 := new(OneCRLSet)

	config.DefineFlags()
	flag.Parse()

	config := config.GetConfig()

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
		err, url := config.GetRecordURL()
		if nil == err {
			set1.FetchData(url, config)
			set2.FetchData(args[0], config)
		}
	} else {
		set1.FetchData(args[0], config)
		set2.FetchData(args[1], config)
	}

	fmt.Printf("set1 has %d entries\n", len((*set1).records.Data))
	fmt.Printf("set2 has %d entries\n", len((*set2).records.Data))

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
