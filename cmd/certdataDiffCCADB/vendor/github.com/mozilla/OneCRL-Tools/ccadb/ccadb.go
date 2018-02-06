/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"time"

	"github.com/mozilla/OneCRL-Tools/certdataDiffCCADB"
)

const (
	URL = "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV"

	CIO  = "Certificate Issuer Organization"
	CIOU = "Certificate Issuer Organizational Unit"
	CN   = "Common Name or Certificate Name"
	CSN  = "Certificate Serial Number"
	FP   = "SHA-256 Fingerprint"
	PEM  = "PEM Info"
	TB   = "Trust Bits"

	TimeFMT = "2006 Jan 01"

	TrustWeb   = "Websites"
	TrustEmail = "Email"
)

type Certificate struct {
	columnMap map[string]int
	row       []string
	lineNum   int
}

func (c *Certificate) Get(attr string) (string, bool) {
	index, ok := c.columnMap[attr]
	if !ok {
		return "", false
	}
	return c.row[index], true
}

func (c *Certificate) ValidFromGMT() (time.Time, error) {
	t, ok := c.Get("Valid From [GMT]")
	if !ok {
		return time.Time{}, errors.New("ValidFromGMT not found.")
	}
	return time.Parse(TimeFMT, t)
}

func (c *Certificate) ValidToGMT() (time.Time, error) {
	t, ok := c.Get("Valid To [GMT]")
	if !ok {
		return time.Time{}, errors.New("ValidToGMT not found.")
	}
	return time.Parse(TimeFMT, t)
}

func (c *Certificate) MarshalJSON() ([]byte, error) {
	m := make(map[string]string)
	for key, v := range c.columnMap {
		m[key] = c.row[v]
	}
	return json.Marshal(m)
}

func NewCertificate(columnMap map[string]int, row []string, lineNum int) *Certificate {
	p := row[columnMap["PEM Info"]]
	row[columnMap["PEM Info"]] = p[1 : len(p)-1]
	return &Certificate{columnMap, row, lineNum}
}

// NewEntry attempts to build a certdataDiffCCADb.Entry from a provided CCADB certificate.
func NewEntry(c *Certificate) *certdataDiffCCADB.Entry {
	var cio string
	var ciou string
	var cn string
	var csn string
	var pem string
	var fp string
	var tb string
	var tw bool
	var te bool
	var ok bool
	if cio, ok = c.Get(CIO); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", CIO)
	}
	if ciou, ok = c.Get(CIOU); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", CIOU)
	}
	if cn, ok = c.Get(CN); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", CN)
	}
	if csn, ok = c.Get(CSN); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", CSN)
	}
	if pem, ok = c.Get(PEM); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", PEM)
	}
	if fp, ok = c.Get(FP); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", FP)
	}
	if tb, ok = c.Get(TB); !ok {
		log.Printf("Failed to find column in CCADB, %v\n", TB)
	}
	tw, te = strings.Contains(tb, TrustWeb), strings.Contains(tb, TrustEmail)
	return certdataDiffCCADB.NewEntry(cio, ciou, cn, csn, pem, fp, tw, te,
		c.lineNum, "ccadb")
}

func ParseToNormalizedForm(stream io.Reader) ([]*certdataDiffCCADB.Entry, error) {
	records, err := Parse(stream)
	if err != nil {
		return nil, err
	}
	entries := make([]*certdataDiffCCADB.Entry, len(records))
	for i, record := range records {
		entries[i] = NewEntry(record)
	}
	return entries, nil
}

func Parse(stream io.Reader) ([]*Certificate, error) {
	records := make([]*Certificate, 0)
	reader := csv.NewReader(stream)
	columnMap := make(map[string]int)
	columns, err := reader.Read()
	if err != nil {
		return records, err
	}
	// Extract column headers from the first row so we don't have to
	// hardcode the column numbers
	for index, attr := range columns {
		columnMap[attr] = index
	}
	lineNum := 1
	for row, err := reader.Read(); err == nil; row, err = reader.Read() {
		lineNum += 1
		records = append(records, NewCertificate(columnMap, row, lineNum))
		lineNum += strings.Count(strings.Join(row, ""), "\n")
	}
	return records, nil
}
