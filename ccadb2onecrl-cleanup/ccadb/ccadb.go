/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const expiredSource = "https://ccadb.my.salesforce-sites.com/mozilla/PublicInterCertsCertExpiredCSV"

// FetchExpiredCertificates retrieves expired certificates from CCADB.
func FetchExpiredCertificates() ([]*Certificate, error) {
	log.Println("Fetching expired certificates from CCADB...")

	resp, err := http.Get(expiredSource)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch expired certificates")
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, errors.Wrap(err, "failed to read CSV data")
	}

	var expiredCerts []*Certificate
	for _, record := range records[1:] { // Skip header
		cert := &Certificate{
			SerialNumber:     record[0],
			RevocationStatus: record[1],
		}
		if cert.RevocationStatus == "Cert Expired" {
			expiredCerts = append(expiredCerts, cert)
		}
	}

	log.Printf("Fetched %d expired certificates.", len(expiredCerts))
	return expiredCerts, nil
}

// UpdateCertificateStatus updates the status of a certificate in CCADB.
func UpdateCertificateStatus(cert *Certificate, newStatus string) error {
	log.Printf("Updating status of certificate %s to %s in CCADB...", cert.SerialNumber, newStatus)

	// Placeholder: API call or database update logic goes here

	return nil
}
