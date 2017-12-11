/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"
	"flag"
	"fmt"
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

var serverMode bool

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&certdataPath, "cd", "", "Path to certdata.txt")
	flag.StringVar(&certdataURL, "cdurl", certdata.URL, "URL to certdata.txt")
	flag.StringVar(&ccadbPath, "ccadb", "", "Path to CCADB report file.")
	flag.StringVar(&ccadbURL, "ccadburl", ccadb.URL, "URL to CCADB report file.")
	flag.StringVar(&outDir, "o", "", "Path to the output directory.")
	flag.BoolVar(&serverMode, "serve", false, "Start in server mode.")
	flag.Parse()

	matchedPath = path.Join(outDir, matched)
	unmatchedTrustPath = path.Join(outDir, unmatchedTrusted)
	unmatchedUntrustedPath = path.Join(outDir, unmatchedUntrusted)
}

// Functions used for single run mode.

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
		r, err := getFromURL(ccadbURL)
		if err != nil {
			log.Fatal("Problem fetching CCADB data from URL %s\n", err)
		}
		return r
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
		r, err := getFromURL(certdataURL)
		// get the stream from URL
		if err != nil {
			log.Fatal("Problem fetching certdata.txt data from URL %s\n", err)
		}
		return r
	}
}

func getFromURL(url string) (io.ReadCloser, error) {
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	return r.Body, nil
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

// Functions used for server mode.

// SimpleEntry is a subset of the certdataDiffCCADB.Entry use to provide a simpler
// view of the certdata file while in server mode.
type SimpleEntry struct {
	PEM         string `json:"PEM"`
	Fingerprint string `json:"sha256"`
	TrustWeb    bool   `json:"trustWeb"`
	TrustEmail  bool   `json:"trustEmail"`
}

// ListCertdata returns to the client a JSON array of SimpleEntry
func ListCertdata(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(fmt.Sprintf("%v\n", err)))
		}
	}()
	q := req.URL.Query()
	url := certdataURL
	if u, ok := q["url"]; ok && len(u) > 0 {
		url = u[0]
	}
	log.Printf("ListCertdata, IP: %v, certdata.txt URL: %v\n", req.RemoteAddr, url)
	stream, err := getFromURL(url)
	if err != nil {
		w.Write([]byte(fmt.Sprintln(err.Error())))
		log.Printf("ListCertdata, IP: %v, Error: %v\n", req.RemoteAddr, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer stream.Close()
	c, err := certdata.ParseToNormalizedForm(stream)
	if err != nil {
		w.Write([]byte(fmt.Sprintln(err.Error())))
		log.Printf("ListCertdata, IP: %v, Error: %v\n", req.RemoteAddr, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resp := make([]SimpleEntry, len(c))
	for _, e := range c {
		resp = append(resp, SimpleEntry{e.PEM, e.Fingerprint, e.TrustEmail, e.TrustWeb})
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		w.Write([]byte(fmt.Sprintln(err.Error())))
		log.Printf("ListCertdata, IP: %v, Error: %v\n", req.RemoteAddr, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

// Runner function for starting the server.
func serve() {
	log.Println("Starting in server mode.")
	// Add handlers.
	http.HandleFunc("/certdata", ListCertdata)
	// Start up the server.
	port := fmt.Sprintf(":%v", os.Getenv("PORT"))
	log.Printf("Listening on port %v\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

// Runner functions for either single run mode or server mode.
func singleRun() {
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

func main() {
	if serverMode {
		serve()
	} else {
		singleRun()
	}
}
