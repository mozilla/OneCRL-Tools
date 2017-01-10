package salesforce

import (
	"encoding/csv"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
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

func FetchRevokedCertInfo(stream io.ReadCloser) []RevokedCertInfo {
	records := FetchSalesforceCSV(stream)
	revoked := make([]RevokedCertInfo, len(records.Rows))

	for _, each := range records.Rows {
		certInfo := RevokedCertInfo{}
		certInfo.Status = each[records.ColumnNames["OneCRL Status"]]
		certInfo.PEM = each[records.ColumnNames["PEM Info"]]
		certInfo.AlternateCRL = each[records.ColumnNames["Alternate CRL"]]
		certInfo.CRLs = strings.Split(each[records.ColumnNames["CRL URL(s)"]] + ", " + certInfo.AlternateCRL, ", ")

		// Also get some data for more helpful errors
		certInfo.CSN = each[records.ColumnNames["Certificate Serial Number"]]
		certInfo.CertName = each[records.ColumnNames["CA Owner/Certificate Name"]]

		revoked = append(revoked, certInfo)
	}

	return revoked
}

func CertDataFromSalesforcePEM (PEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(strings.Replace(PEM, "'", "", -1)))
	if block != nil {
		return block.Bytes, nil
	}
	return nil, errors.New("can't decode PEM data")
}
