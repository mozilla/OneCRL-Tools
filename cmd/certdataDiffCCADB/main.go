/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

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

// Constants for generating and self signing a TLS cert for server mode.
const (
	CertDir = "/tmp"
	Private = "private.pem"
	Public  = "public.pem"
	Cert    = "cert.pem"
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
var addr string
var port string
var encrypt bool
var public string
var private string
var cert string

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&certdataPath, "cd", "", "Path to certdata.txt")
	flag.StringVar(&certdataURL, "cdurl", certdata.URL, "URL to certdata.txt")
	flag.StringVar(&ccadbPath, "ccadb", "", "Path to CCADB report file.")
	flag.StringVar(&ccadbURL, "ccadburl", ccadb.URL, "URL to CCADB report file.")
	flag.StringVar(&outDir, "o", "", "Path to the output directory.")
	flag.BoolVar(&serverMode, "serve", false, "Start in server mode.")
	flag.StringVar(&addr, "address", "127.0.0.1", "Address to listen on while in server mode.")
	flag.StringVar(&port, "port", "1443", "Port to listen on while in server mode.")
	flag.Parse()

	matchedPath = path.Join(outDir, matched)
	unmatchedTrustPath = path.Join(outDir, unmatchedTrusted)
	unmatchedUntrustedPath = path.Join(outDir, unmatchedUntrusted)

	public = path.Join(CertDir, Public)
	private = path.Join(CertDir, Private)
	cert = path.Join(CertDir, Cert)
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

// CertTemplate generates a bare minimum template use for x509.CreateCertificate.
// Credit to https://ericchiang.github.io/post/go-tls/ for saving a lot of time figuring out
// the bare minimum required.
func CertTemplate() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Mozilla"}},
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 31 * 12 * 100), // Why not 100 years?
		BasicConstraintsValid: true,
	}
	tmpl.IsCA = false
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	return &tmpl, nil
}

// GenerateTLSCert generates an ECDSA key pair over a P384 curve, as well as a
// self signed certificate, and writes the encoded PEMs to the provided file paths.
//
// Many - MANY - erros may occur. This function logs and exits on any errors.
func GenerateTLSCertOrDie(publicName, privateName, certName string) {
	// Generate an ECDSA key pair.
	private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	public := private.Public()
	// CreateCertificate requires that a "template" be given, so generate an empty cert object
	// with the basic required fields.
	template, err := CertTemplate()
	if err != nil {
		log.Fatal(err)
	}
	// Self Sign.
	cert, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		log.Fatal(err)
	}
	// Marshal in memory PEMs to bytes.
	privKey, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		log.Fatal(err)
	}
	// Encode and write the key pair and self signed cert to disk.
	privF, err := os.Create(privateName)
	defer privF.Close()
	if err != nil {
		log.Fatal(err)
	}
	pubF, err := os.Create(publicName)
	defer pubF.Close()
	if err != nil {
		log.Fatal(err)
	}
	certF, err := os.Create(certName)
	defer certF.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(privF, &pem.Block{"EC PRIVATE KEY", make(map[string]string, 0), privKey})
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(pubF, &pem.Block{"EC PUBLIC KEY", make(map[string]string, 0), pubKey})
	if err != nil {
		log.Fatal(err)
	}
	err = pem.Encode(certF, &pem.Block{"CERTIFICATE", make(map[string]string, 0), cert})
	if err != nil {
		log.Fatal(err)
	}
}

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
	q := req.URL.Query()
	url := certdataURL
	if u, ok := q["url"]; ok && len(u) > 0 {
		url = u[0]
	}
	log.Printf("ListCertdata, IP: %v, certdata.txt URL: %v\n", req.RemoteAddr, url)
	stream, err := getFromURL(url)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintln(err.Error())))
		log.Printf("ListCertdata, IP: %v, Error: %v\n", req.RemoteAddr, err)
		return
	}
	defer stream.Close()
	c, err := certdata.ParseToNormalizedForm(stream)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintln(err.Error())))
		log.Printf("ListCertdata, IP: %v, Error: %v\n", req.RemoteAddr, err)
		return
	}
	resp := make([]SimpleEntry, len(c))
	for _, e := range c {
		resp = append(resp, SimpleEntry{e.PEM, e.Fingerprint, e.TrustEmail, e.TrustWeb})
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintln(err.Error())))
		log.Printf("ListCertdata, IP: %v, Error: %v\n", req.RemoteAddr, err)
		return
	}
	w.WriteHeader(http.StatusOK)
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

func serve() {
	log.Println("Starting in server mode.")
	// Add handlers.
	http.HandleFunc("/hello", ListCertdata)
	// Encrypt, but we don't particularly need authetication,
	// so self signed cert it is.
	log.Printf("Generating new TLS certificate.")
	GenerateTLSCertOrDie(public, private, cert)
	// Start up the server.
	address := fmt.Sprintf("%v:%v", addr, port)
	log.Printf("Listening on %v\n", address)
	log.Fatal(http.ListenAndServeTLS(address, cert, private, nil))
}

func main() {
	if serverMode {
		serve()
	} else {
		singleRun()
	}
}
