/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"sync"

	"github.com/mozilla/OneCRL-Tools/ccadb"
	"github.com/mozilla/OneCRL-Tools/certdata"
	"github.com/mozilla/OneCRL-Tools/certdataDiffCCADB"
)

// Hard coded output filenames.
const (
	matched            = "matched.json"
	unmatchedTrusted   = "unmatchedTrusted.json"
	unmatchedUntrusted = "unmatchedUntrusted.json"
)

var certdataURL string
var ccadbURL string
var certdataPath string
var ccadbPath string

var outDir string

var matchedPath string
var unmatchedTrustPath string
var unmatchedUntrustedPath string

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&certdataPath, "cd", "", "Path to certdata.txt")
	flag.StringVar(&certdataURL, "cdurl", certdata.URL, "URL to certdata.txt")
	flag.StringVar(&ccadbPath, "ccadb", "", "Path to CCADB report file.")
	flag.StringVar(&ccadbURL, "ccadburl", ccadb.URL, "URL to CCADB report file.")
	flag.StringVar(&outDir, "o", "", "Path to the output directory.")
	flag.Parse()

	matchedPath = path.Join(outDir, matched)
	unmatchedTrustPath = path.Join(outDir, unmatchedTrusted)
	unmatchedUntrustedPath = path.Join(outDir, unmatchedUntrusted)
}

// CCCADBReader constructs an io.ReaderCloser depending on the results
// of parsing the CLI flags. The presence of a filepath will return an io.ReadCloser
// with a concrete type of os.File. Otherwise, the io.ReadCloser is backed by
// and http.Response which is pulling the data from the URL parsed in the CLI flags.
func CCADBReader() io.ReadCloser {
	if ccadbPath != "" {
		log.Printf("Loading CCADB data from %s\n", ccadbPath)
		// get the stream from a file
		stream, err := os.Open(ccadbPath)
		if err != nil {
			log.Fatal("Problem loading CCADB data from file %s\n", err)
		}
		return stream
	} else {
		log.Printf("Loading CCADB data from %s\n", ccadbURL)
		// get the stream from URL
		r, err := http.Get(ccadbURL)
		if err != nil {
			log.Fatal("Problem fetching CCADB data from URL %s\n", err)
		}
		return r.Body
	}
}

// CertdataReader constructs an io.ReaderCloser depending on the results
// of parsing the CLI flags. The presence of a filepath will return an io.ReadCloser
// with a concrete type of os.File. Otherwise, the io.ReadCloser is backed by
// and http.Response which is pulling the data from the URL parsed in the CLI flags.
func CertdataReader() io.ReadCloser {
	if certdataPath != "" {
		log.Printf("Loading certdata.txt data from %s\n", certdataPath)
		// get the stream from a file
		stream, err := os.Open(certdataPath)
		if err != nil {
			log.Fatal("Problem loading certdata.txt data from file %s\n", err)
		}
		return stream
	} else {
		log.Printf("Loading certdata.txt data from %s\n", certdataURL)
		// get the stream from URL
		r, err := http.Get(certdataURL)
		if err != nil {
			log.Fatal("Problem fetching certdata.txt data from URL %s\n", err)
		}
		return r.Body
	}
}

func writeJSON(v interface{}, fname string, wg *sync.WaitGroup) {
	defer wg.Done()
	f, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	j, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		log.Fatal(err)
		return
	}
	if _, err := f.Write(j); err != nil {
		log.Fatal(err)
	}
}

func parse(src func() io.ReadCloser, parser func(io.Reader) ([]*certdataDiffCCADB.Entry, error), out chan<- []*certdataDiffCCADB.Entry) {
	r := src()
	defer r.Close()
	result, err := parser(r)
	if err != nil {
		log.Println(err)
		out <- nil
		return
	}
	out <- result
}

func main() {
	cdResult := make(chan []*certdataDiffCCADB.Entry)
	CCADBResult := make(chan []*certdataDiffCCADB.Entry)
	go parse(CertdataReader, certdata.ParseToNormalizedForm, cdResult)
	go parse(CCADBReader, ccadb.ParseToNormalizedForm, CCADBResult)
	cd := <-cdResult
	ccadb := <-CCADBResult
	if cd == nil || ccadb == nil {
		log.Fatal("One or more errors have occurred.")
	}
	matched, unmatchedT, unmatchedUT := certdataDiffCCADB.MapPairs(cd, ccadb)
	wg := new(sync.WaitGroup)
	wg.Add(3)
	go writeJSON(matched, matchedPath, wg)
	go writeJSON(unmatchedT, unmatchedTrustPath, wg)
	go writeJSON(unmatchedUT, unmatchedUntrustedPath, wg)
	wg.Wait()
}
