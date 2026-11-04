/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// updateSupplemental updates ccadb2OneCRL/prune/supplemental.json.
//
// It removes the entries that are no longer in OneCRL, and adds entries for
// the issuer:serial entries in OneCRL that neither the CCADB report of revoked
// intermediates nor supplemental.json covers. Certificates for new entries are
// looked up in the CCADB's reports of intermediates and included roots, and
// then on crt.sh. Entries whose certificate cannot be found are listed, but
// not added.
//
// Usage, from the root of the repository:
//
//	go run ./ccadb2OneCRL/updateSupplemental [-dry-run]
package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/zmap/zcrypto/x509"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/prune"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/utils"
)

const (
	oneCRLDefault        = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records"
	crtshDefault         = "host=crt.sh port=5432 user=guest dbname=certwatch sslmode=disable connect_timeout=30"
	intermediatesSource  = "https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV"
	includedRootsSource  = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"
	crtshSerialsPerQuery = 100
)

func main() {
	file := flag.String("file", "ccadb2OneCRL/prune/supplemental.json", "path to supplemental.json")
	oneCRLURL := flag.String("onecrl", oneCRLDefault, "URL of the published OneCRL records")
	crtshDSN := flag.String("crtsh", crtshDefault, "connection string for crt.sh's PostgreSQL database")
	dryRun := flag.Bool("dry-run", false, "report the changes without writing supplemental.json")
	flag.Parse()
	if err := run(*file, *oneCRLURL, *crtshDSN, *dryRun); err != nil {
		fmt.Fprintf(os.Stderr, "updateSupplemental: %v\n", err)
		os.Exit(1)
	}
}

func run(file, oneCRLURL, crtshDSN string, dryRun bool) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var existing []prune.SupplementalEntry
	if err := json.Unmarshal(data, &existing); err != nil {
		return errors.Wrapf(err, "malformed %s", file)
	}
	records, err := fetchOneCRL(oneCRLURL)
	if err != nil {
		return err
	}
	revoked, err := fetchCertificates(ccadb.RevokedIntermediatesSource)
	if err != nil {
		return err
	}
	other, err := fetchCertificates(intermediatesSource, includedRootsSource)
	if err != nil {
		return err
	}
	res, err := update(existing, records, revoked, other, queryCrtsh(crtshDSN))
	if err != nil {
		return err
	}

	report := func(verb string, entries []prune.SupplementalEntry) {
		fmt.Fprintf(os.Stderr, "%s %d entries\n", verb, len(entries))
		for _, entry := range entries {
			fmt.Fprintf(os.Stderr, "  %s serial %s (%s)\n", entry.Issuer, entry.Serial, entry.Bug)
		}
	}
	report("removed", res.removed)
	report("added", res.added)
	fmt.Fprintf(os.Stderr, "%d issuer:serial entries in OneCRL have no known certificate\n", len(res.unknown))
	for _, record := range res.unknown {
		issuer, _ := utils.B64Decode(record.IssuerName)
		serial, _ := utils.B64Decode(record.SerialNumber)
		fmt.Fprintf(os.Stderr, "  %s serial %X (%s)\n", utils.NameString(issuer), normalizeSerial(serial), record.Details.Bug)
	}
	if dryRun {
		return nil
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(res.entries); err != nil {
		return err
	}
	return os.WriteFile(file, out.Bytes(), 0o644)
}

var client = &http.Client{Timeout: 5 * time.Minute}

func fetchOneCRL(url string) ([]*onecrl.Record, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch OneCRL")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching OneCRL returned status %d", resp.StatusCode)
	}
	var collection onecrl.OneCRL
	if err := json.NewDecoder(resp.Body).Decode(&collection); err != nil {
		return nil, errors.Wrap(err, "malformed OneCRL records")
	}
	return collection.Data, nil
}

func fetchCertificates(urls ...string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	for _, url := range urls {
		records, err := ccadb.FromURL(url)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch %s", url)
		}
		for _, record := range records {
			if cert, err := record.ParseCertificate(); err == nil {
				certs = append(certs, cert)
			}
		}
	}
	return certs, nil
}

// queryCrtsh looks up certificates by serial number in crt.sh's database.
// The query is built without bind parameters, so that it is sent with the
// simple query protocol. The serial numbers are hex encoded, so they are safe
// to include in the query.
func queryCrtsh(dsn string) lookupFunc {
	return func(serials [][]byte) ([]crtshCert, error) {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		certs := make([]crtshCert, 0)
		for start := 0; start < len(serials); start += crtshSerialsPerQuery {
			end := min(start+crtshSerialsPerQuery, len(serials))
			values := make([]string, 0)
			for _, serial := range serials[start:end] {
				// crt.sh has the serial number as it is encoded in the
				// certificate, which may have a leading zero byte.
				values = append(values, fmt.Sprintf("decode('%s', 'hex')", hex.EncodeToString(serial)))
				if serial[0]&0x80 != 0 {
					values = append(values, fmt.Sprintf("decode('00%s', 'hex')", hex.EncodeToString(serial)))
				}
			}
			query := "SELECT c.id, c.certificate FROM certificate c WHERE x509_serialNumber(c.certificate) IN (" +
				strings.Join(values, ", ") + ")"
			rows, err := db.Query(query)
			if err != nil {
				return nil, errors.Wrap(err, "crt.sh query failed")
			}
			for rows.Next() {
				var id int64
				var der []byte
				if err := rows.Scan(&id, &der); err != nil {
					rows.Close()
					return nil, err
				}
				if cert, err := x509.ParseCertificate(der); err == nil {
					certs = append(certs, crtshCert{id: fmt.Sprint(id), cert: cert})
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, err
			}
		}
		return certs, nil
	}
}
