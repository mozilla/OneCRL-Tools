package salesforce

import (
	"encoding/csv"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"net/http"
	"strings"
)

type SalesforceCSV struct {
	ColumnNames map[string]int
	Rows [][]string
}

type RevokedCertInfo struct {
	Status		  string
	PEM			  string
	AlternateCRL  string
	CRLs		  []string
	CSN			  string
	CertName	  string
	SerialNumber  string
	Reason		  string
}

func FetchSalesforceCSV(stream io.ReadCloser) SalesforceCSV {
	records := SalesforceCSV{}

	reader := csv.NewReader(stream)
	reader.FieldsPerRecord = 0
	rawCSVData, err := reader.ReadAll()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	columnMap := make(map[string]int)
	
	// Extract column headers from the first row so we don't have to
	// hardcode the column numbers
	for this, that := range rawCSVData[0] {
		columnMap[that] = this
	}
	records.ColumnNames = columnMap

	records.Rows = rawCSVData[1:]

	return records
}

func FetchRevokedCertInfoFrom(location string) ([]RevokedCertInfo, error) {
	var stream io.ReadCloser

	if 0 == strings.Index(strings.ToUpper(location), "HTTP") {
		if 0 != strings.Index(strings.ToUpper(location), "HTTPS") {
			// cowardly refuse to get cert info from a non-https URL
			return make([]RevokedCertInfo, 0), errors.New("Cowardly refusing to load data from a non-HTTPS URL")
		}
		fmt.Printf("loading salesforce data from %s\n", location)

		// get the stream from URL
		r, err := http.Get(location)
		if err != nil {
			return make([]RevokedCertInfo, 0), errors.New(fmt.Sprintf("problem fetching salesforce data from URL %s\n", err))
		}
		defer r.Body.Close()

		stream = r.Body
	} else {
		fmt.Printf("loading salesforce data from %s\n", location)
		// get the stream from a file
		csvfile, err := os.Open(location)
		if err != nil {
			return make([]RevokedCertInfo, 0), errors.New(fmt.Sprintf("problem loading salesforce data from file %s\n", err))
		}

		stream = io.ReadCloser(csvfile)
	}

	return FetchRevokedCertInfo(stream), nil
}

func FetchRevokedCertInfo(stream io.ReadCloser) []RevokedCertInfo {
	records := FetchSalesforceCSV(stream)
	certs := make([]RevokedCertInfo, 0)

	for _, each := range records.Rows {
		certInfo := RevokedCertInfo{}
		certInfo.Status = each[records.ColumnNames["OneCRL Status"]]
		certInfo.PEM = each[records.ColumnNames["PEM Info"]]
		certInfo.AlternateCRL = each[records.ColumnNames["Alternate CRL"]]
		certInfo.CRLs = strings.Split(each[records.ColumnNames["CRL URL(s)"]] + ", " + certInfo.AlternateCRL, ", ")
		certInfo.Reason= each[records.ColumnNames["RFC 5280 Revocation Reason Code"]]

		// Also get some data for more helpful errors
		certInfo.CSN = each[records.ColumnNames["Certificate Serial Number"]]
		certInfo.CertName = each[records.ColumnNames["CA Owner/Certificate Name"]]

		// And get some data for reconciling OneCRL entries and CCADB entries
		// for reporting
		certInfo.SerialNumber= each[records.ColumnNames["Certificate Serial Number"]]

		certs = append(certs, certInfo)
	}

	return certs
}

func CertDataFromSalesforcePEM (PEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(strings.Replace(PEM, "'", "", -1)))
	if block != nil {
		return block.Bytes, nil
	}
	return nil, errors.New("can't decode PEM data")
}
