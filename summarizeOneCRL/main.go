package main

import (
	"bufio"
	constraintsx509  "github.com/jcjones/constraintcrypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/mozilla/OneCRL-Tools/config"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
	"github.com/mozilla/OneCRL-Tools/salesforce"
	"github.com/mozilla/OneCRL-Tools/util"	
	"os"
	"strings"
)

type ReportLine struct {
	Created string
	Why string
	Summary string
	Bug string
	BugURL string
	SerialNumber string
	IssuerName string
	SubjectName string
	NotAfter  string
}

func GetReportLines(conf *config.OneCRLConfig, urlPtr *string) ([]ReportLine, error) {
	existing, err := oneCRL.FetchExistingRecords(conf.KintoCollectionURL + "/records")
	reportLines := make([]ReportLine, 0)

	revokedCerts, err := salesforce.FetchRevokedCertInfoFrom(*urlPtr)

	revocationInfoToCCADBEntry := make(map[string] salesforce.RevokedCertInfo)
	for idx, revoked := range revokedCerts {
		// make a map of issuer/serial to revoked
		certData, err:= salesforce.CertDataFromSalesforcePEM(revoked.PEM)
		if err != nil {
			fmt.Printf("(%d, %s, %s) can't decode PEM %s\n%v\n", idx, revoked.CSN, revoked.CertName, revoked.PEM, revoked)
			continue
		}

		cert, err := constraintsx509.ParseCertificate(certData)
		if err != nil {
			fmt.Printf("(%s, %s) could not parse cert\n", revoked.CSN, revoked.CertName)
			continue
		}

		issuerString := base64.StdEncoding.EncodeToString(cert.RawIssuer)
		serialBytes, err := asn1.Marshal(cert.SerialNumber)

		if err != nil {
			fmt.Printf("(%s, %s) could not marshal serial number\n", revoked.CSN, revoked.CertName)
			continue
		}

		serialString := base64.StdEncoding.EncodeToString(serialBytes[2:])
		
		if false {
			fmt.Printf("Look! %s %s\n", issuerString, serialString);
		}

		revocationInfoToCCADBEntry[oneCRL.StringFromIssuerSerial(issuerString, serialString)] = revoked
	}

	if err != nil  {
		return reportLines, err
	}

	bugsOfInterest := make([]string, 0)

	for _, entry := range existing.Data {
		reportLine:= ReportLine{}
		// grab a CCADB entry:
		CCADBEntry := revocationInfoToCCADBEntry[oneCRL.StringFromIssuerSerial(entry.IssuerName, entry.SerialNumber)]

		// TODO: Parse date, make it human readible?
		reportLine.Created = entry.Details.Created
		reportLine.Why = entry.Details.Why
		// if there's no "why" detail in OneCRL, get the reason info from CCADB
		if 1 >= len(entry.Details.Why) {
			reportLine.Why = CCADBEntry.Reason
		}

		reportLine.Bug = entry.Details.Bug

		// attempt to parse out URL parts if it's an URL
		if 0 == strings.Index(strings.ToUpper(entry.Details.Bug), "HTTPS://") {
			reportLine.BugURL = entry.Details.Bug
			// if we can parse out the actual bug string, do so
			bugURLParts := strings.Split(entry.Details.Bug, "?id=")
			if len(bugURLParts) == 2 {
				reportLine.Bug = bugURLParts[1]
			}
		}

		// TODO: Decode the serial number into a (readible) hex representation
		reportLine.SerialNumber, _ = oneCRL.SerialToString(entry.SerialNumber, false, false)

		reportLine.IssuerName, _ = oneCRL.DNToRFC4514(entry.IssuerName)
		fmt.Printf("blah %s\n",reportLine.IssuerName)

		reportLine.SubjectName = CCADBEntry.CertName

		reportLine.NotAfter = CCADBEntry.ValidTo

		// collect the bug number for subsequent summary addition
		if 0 != len(reportLine.Bug) {
			bugsOfInterest = append(bugsOfInterest, reportLine.Bug)
		}

		reportLines = append(reportLines, reportLine)
	}

	searchResponse, err := bugs.GetBugData(bugsOfInterest, conf)
	if nil != err {
		return reportLines, err
	}

	bugMap := make(map[string] bugs.BugData)

	for _, bug := range(searchResponse.Bugs) {
		bugMap[fmt.Sprintf("%d", bug.Id)] = bug
	}

	// loop over the report lines and fill in the summary from the bug
	for idx, reportLine := range(reportLines) {
		reportLines[idx].Summary = bugMap[reportLine.Bug].Summary
	}

	return reportLines, nil
}

func renderToHTML(reportLines []ReportLine, filename string) {
	f, err := os.Create(filename)
	if nil != err {
		panic(err)
	}

	w := bufio.NewWriter(f)

	defer f.Close()
	w.WriteString("<html><table>\n")
	w.WriteString("<tr>")
	w.WriteString("<td>Created</td>")
	w.WriteString("<td>Why</td>")
	w.WriteString("<td>Summary</td>")
	w.WriteString("<td>Bug</td>")
	w.WriteString("<td>Serial number</td>")
	w.WriteString("<td>Issuer name</td>")
	w.WriteString("<td>Subject name</td>")
	w.WriteString("<td>Not after</td>")
	w.WriteString("</tr>\n")
	
	for _, reportLine := range(reportLines) {
		w.WriteString("<tr>")
		w.WriteString(fmt.Sprintf("<td>%s</td>", reportLine.Created))
		w.WriteString(fmt.Sprintf("<td>%s</td>", reportLine.Why))
		w.WriteString(fmt.Sprintf("<td>%s</td>", reportLine.Summary))
		if 0 != len(reportLine.BugURL) {
			w.WriteString(fmt.Sprintf("<td><a href=\"%s\">%s</a></td>", reportLine.BugURL, reportLine.Bug))
		} else {
			w.WriteString(fmt.Sprintf("<td>%s</td>", reportLine.Bug))
		}

		w.WriteString(fmt.Sprintf("<td>%s</td>", reportLine.SerialNumber))
		w.WriteString(fmt.Sprintf("<td>%s</td>", reportLine.IssuerName))
		w.WriteString(fmt.Sprintf("<td>%s</td>", reportLine.SubjectName))
		w.WriteString(fmt.Sprintf("<td>%s</td>", reportLine.NotAfter))
		w.WriteString("</tr>\n")
	}
	
	w.WriteString("</table></html>\n")

	w.Flush()
}

func main() {
	urlPtr := flag.String("url", "https://ccadb-public.secure.force.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV", "the URL of the salesforce data")
	typePtr := flag.String("type", "html", "the type of report to generate")
	outFilePtr := flag.String("outfile", "report", "the filename of the report to create")
	
	config.DefineFlags()
	flag.Parse()
	conf := config.GetConfig()

	reportLines, err := GetReportLines(conf, urlPtr)
	if nil != err {
		panic(err)
	}

	// render the report
	if "HTML" == strings.ToUpper(*typePtr) {
		renderToHTML(reportLines, *outFilePtr)
	}
}
