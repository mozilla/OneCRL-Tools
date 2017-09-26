package main

import (
	"flag"
	"fmt"
	"github.com/mozilla/OneCRL-Tools/oneCRL"	
	"github.com/mozilla/OneCRL-Tools/config"	
)

func main() {
	config.DefineFlags()
	flag.Parse()

	rev := new (oneCRL.RevocationsTxtData)
	
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
