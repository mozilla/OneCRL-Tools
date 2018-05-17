package cmd

import (
	"log"
	"net/http"
	"runtime"
	"sync"

	"github.com/mozilla/OneCRL-Tools/ccadb"
	"github.com/mozilla/OneCRL-Tools/certdataDiffCCADB"
	"github.com/mozilla/OneCRL-Tools/obsDiffCCADB/db"
	"github.com/mozilla/OneCRL-Tools/observatory"
)

func getCCADB(url string) ([]*ccadb.Certificate, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []*ccadb.Certificate{}, err
	}
	req.Header.Add("X-Automated-Tool", `https://github.com/mozilla/OneCRL-Tools obsDiffCCADB"`)
	log.Printf("Loading salesforce data from %s\n", url)
	r, err := http.Get(url)
	if err != nil {
		log.Fatalf("Problem fetching salesforce data from URL %s\n", err)
	}
	defer r.Body.Close()
	return ccadb.Parse(r.Body)
}

func getObservatory(entries []*ccadb.Certificate) []*observatory.Certificate {
	numWorkers := runtime.NumCPU()
	results := make([]*observatory.Certificate, 0)
	in := make(chan *ccadb.Certificate, numWorkers)
	out := make(chan *observatory.Certificate, numWorkers)
	wg := &sync.WaitGroup{}
	// Result aggregation goroutine.
	go func() {
		defer wg.Done()
		for r := range out {
			results = append(results, r)
		}
	}()
	for i := 0; i < numWorkers; i++ {
		// Worker goroutines to get multiple Observatory results asynchronously.
		go func() {
			wg.Add(1)
			defer wg.Done()
			for cert := range in {
				if cert.GetOrPanic("PEM Info") == "" {
					j, err := cert.MarshalJSON()
					if err != nil {
						log.Println(err)
						continue
					}
					log.Printf("No PEM was parsed from the following entry:\n%v\n", string(j))
					continue
				}
				obsCert, err := observatory.ParseFromObservatory(certdataDiffCCADB.NormalizePEM(cert.GetOrPanic("PEM Info")))
				if err != nil {
					log.Printf("Error: %v\nFingerprint: %v\n", err.Error(), cert.GetOrPanic("SHA-256 Fingerprint"))
					continue
				}
				out <- obsCert
			}
		}()
	}
	for _, e := range entries {
		in <- e
	}
	close(in)
	// Wait for the fetchers.
	wg.Wait()
	// Use the same workgroup to wait for the result goroutine.
	wg.Add(1)
	close(out)
	wg.Wait()
	return results
}

// MakeDB pulls data from the CCADB as well as the TLS Observatory and
// normalizes them to a standard form. The result is persisted in a
// SQLite3 database.
func MakeDB(contentDir string) {
	db.Initialize(db.Wipe, contentDir)
	intermediates, err := getCCADB(ccadb.IntermediateReportURL)
	if err != nil {
		panic(err)
	}
	roots, err := getCCADB(ccadb.RootReportURL)
	if err != nil {
		panic(err)
	}
	db.PersistCCADBIntermediates(intermediates)
	db.PersistCCADBRoots(roots)
	obsIntermediates := getObservatory(intermediates)
	obsRoots := getObservatory(roots)
	db.PersistObservatoryIntermediates(obsIntermediates)
	db.PersistObservatoryRoots(obsRoots)
}
