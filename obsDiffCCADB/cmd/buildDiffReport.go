package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/mozilla/OneCRL-Tools/obsDiffCCADB"
	"github.com/mozilla/OneCRL-Tools/obsDiffCCADB/db"
)

var intermediateSchema = map[string]string{"PEM Info": "string",
	"SHA-1 Fingerprint":                      "string",
	"Certificate ID":                         "string",
	"Certificate Issuer Common Name":         "string",
	"Certificate Issuer Organization":        "csv",
	"Certificate Issuer Organizational Unit": "csv",
	"Public Key Algorithm":                   "string",
	"Certificate Serial Number":              "string",
	"Signature Hash Algorithm":               "string",
	"Certificate Subject Common Name":        "string",
	"Certificate Subject Organization":       "csv",
	"Valid From [GMT]":                       "string",
	"Valid To [GMT]":                         "string",
	"CRL URL(s)":                             "csv",
	"Extended Key Usage":                     "csv",
	"Technically Constrained":                "string"}

var rootSchema = map[string]string{"CA Owner": "string",
	"Root Certificate Name":                  "string",
	"Certificate Issuer Common Name":         "string",
	"Certificate Issuer Organization":        "csv",
	"Certificate Issuer Organizational Unit": "csv",
	"Certificate Subject Common Name":        "string",
	"Certificate Subject Organization":       "csv",
	"Certificate Subject Organization Unit":  "csv",
	"Subject":                                "string",
	"Valid From [GMT]":                       "string",
	"Valid To [GMT]":                         "string",
	"Certificate Serial Number":              "string",
	"Signature Hash Algorithm":               "string",
	"Public Key Algorithm":                   "string",
	"SHA-1 Fingerprint":                      "string",
	"Certificate ID":                         "string",
	"PEM Info":                               "string"}

const intermediateQuery = `
SELECT c.'SHA-256 Fingerprint', c.'%v', o.'%v'
FROM ccadbIntermediateNormalized AS c JOIN
	 observatoryIntermediate AS o
	 ON c.'SHA-256 Fingerprint' == o.'SHA-256 Fingerprint'
WHERE c.'%v' != o.'%v'
`

const rootQuery = `
SELECT c.'SHA-256 Fingerprint', c.'%v', o.'%v'
FROM ccadbRootNormalized AS c JOIN
	 observatoryRoot AS o
	 ON c.'SHA-256 Fingerprint' == o.'SHA-256 Fingerprint'
WHERE c.'%v' != o.'%v'
`

func stoset(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// SymmetricDiff lists out the entries that the CCADB has that
// the Observatory does not, as well as the entries that the
// Observatory has that the CCADB does not.
type SymmetricDiff struct {
	Fingerprint    string
	CCADB          []string
	Observatory    []string
	CCADBRaw       string
	ObservatoryRaw string
}

// NewSymmetricDifference constructs a symmetric difference of the provided
// CCADB and Obsevatory field of the given fingerprint and field type (single string/CSV).
func NewSymmetricDifference(fingerprint, ccadbS, obsS, typ string) (SymmetricDiff, bool) {
	var ccadb map[string]bool
	var obs map[string]bool
	switch typ {
	case "string":
		ccadb = map[string]bool{ccadbS: true}
		obs = map[string]bool{obsS: true}
	case "csv":
		ccadb = stoset(obsDiffCCADB.CSVToSlice(ccadbS))
		obs = stoset(obsDiffCCADB.CSVToSlice(obsS))
	}
	for k := range obs {
		delete(obs, k)
		obs[strings.Replace(k, `"`, "", -1)] = true
	}
	diff := SymmetricDiff{Fingerprint: fingerprint, CCADBRaw: ccadbS, ObservatoryRaw: obsS}
	isDiff := false
	for value := range ccadb {
		if _, ok := obs[value]; !ok {
			isDiff = true
			diff.CCADB = append(diff.CCADB, value)
		}
	}
	for value := range obs {
		if _, ok := ccadb[value]; !ok {
			isDiff = true
			diff.Observatory = append(diff.Observatory, value)
		}
	}
	return diff, isDiff
}

// FinalReport is a mapping of differing field values
// to their offending certificate fingerprints.
type FinalReport struct {
	CCADB       map[string][]string
	Observatory map[string][]string
}

// NewFinalReport builds a convenient mapping of the
// symmetric differnce of the CCADB and Observatory.
func NewFinalReport(diffs []SymmetricDiff) FinalReport {
	f := FinalReport{make(map[string][]string), make(map[string][]string)}
	for _, d := range diffs {
		for _, v := range d.CCADB {
			if _, ok := f.CCADB[v]; !ok {
				f.CCADB[v] = make([]string, 0)
			}
			f.CCADB[v] = append(f.CCADB[v], d.Fingerprint)
		}
		for _, v := range d.Observatory {
			if _, ok := f.Observatory[v]; !ok {
				f.Observatory[v] = make([]string, 0)
			}
			f.Observatory[v] = append(f.Observatory[v], d.Fingerprint)
		}
	}
	return f
}

// BuildReport constructs a report of symmetric differences for all columns in the DB.
// Results are written to a JSON file named after each individual column.
func BuildReport(schema map[string]string, query, dirname string) {
	if err := os.MkdirAll(dirname, os.ModePerm); err != nil {
		log.Panic(err)
	}
	// Strip the tricky characters from the column names so we can use them as file names.
	r := regexp.MustCompile(`(\s+|-|\[|\])`)
	for column, typ := range schema {
		report := BuildReportForColumn(query, column, typ)
		fname := path.Join(dirname, r.ReplaceAllString(column, ""))
		WriteReport(report, fname)
	}
}

// BuildReportForColumn constructs a symmetric difference report for a single column.
func BuildReportForColumn(query, column, typ string) FinalReport {
	rows := db.Diffs(fmt.Sprintf(query, column, column, column, column), column)
	diffs := make([]SymmetricDiff, 0)
	for _, r := range rows {
		if diff, isDiff := NewSymmetricDifference(r.Fingerprint, r.CCADB, r.Observatory, typ); isDiff {
			diffs = append(diffs, diff)
		}
	}
	return NewFinalReport(diffs)
}

// WriteReport writes a report to disk as a JSON object.
func WriteReport(fr FinalReport, fname string) {
	j, err := json.MarshalIndent(fr, "", "    ")
	if err != nil {
		log.Panic(err)
	}
	f, err := os.Create(fname)
	if err != nil {
		log.Panic(err)
	}
	defer f.Close()
	f.Write(j)
}

// BuildDiffReport generates and persists to disk a report of the symmetric difference
// between the CCADB and the TLS Observatory.
func BuildDiffReport(contentDir string) {
	db.Initialize(db.DontWipe, contentDir)
	BuildReport(intermediateSchema, intermediateQuery, path.Join(contentDir, "intermediate"))
	BuildReport(rootSchema, rootQuery, path.Join(contentDir, "root"))
}
