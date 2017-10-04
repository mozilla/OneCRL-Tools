/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"flag"
	"fmt"
	"github.com/mozilla/OneCRL-Tools/config"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
)

func main() {
	config.DefineFlags()
	flag.Parse()

	rev := new(oneCRL.RevocationsTxtData)

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
