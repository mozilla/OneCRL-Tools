/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"bufio"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	constraintsx509 "github.com/jcjones/constraintcrypto/x509"
	"github.com/mozilla/OneCRL-Tools/config"
	"github.com/mozilla/OneCRL-Tools/oneCRL"
	"github.com/mozilla/OneCRL-Tools/salesforce"
	"github.com/mozilla/OneCRL-Tools/util"
	"os"
	"strings"
)

type ReportLine struct {
	Created      string
	Why          string
	Summary      string
	Bug          string
	BugURL       string
	SerialNumber string
	IssuerName   string
	SubjectName  string
	NotAfter     string
}

func GetReportLines(conf *config.OneCRLConfig, urlPtr *string) ([]ReportLine, error) {
	reportLines := make([]ReportLine, 0)

	existing, err := oneCRL.FetchExistingRevocations(conf.KintoCollectionURL + "/records")

	if err != nil {
		return reportLines, err
	}

	revokedCerts, err := salesforce.FetchRevokedCertInfoFrom(*urlPtr)

	if err != nil {
		return reportLines, err
	}

	revocationInfoToCCADBEntry := make(map[string]salesforce.RevokedCertInfo)
	for idx, revoked := range revokedCerts {
		// make a map of issuer/serial to revoked
		certData, err := salesforce.CertDataFromSalesforcePEM(revoked.PEM)
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
		revocationInfoToCCADBEntry[oneCRL.StringFromIssuerSerial(issuerString, serialString)] = revoked
	}

	bugsOfInterest := make([]string, 0)

	for _, entry := range existing.Data {
		reportLine := ReportLine{}
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

		reportLine.SerialNumber, err = oneCRL.SerialToString(entry.SerialNumber, false, false)

		if err != nil {
			return reportLines, err
		}

		reportLine.IssuerName, err = oneCRL.DNToRFC4514(entry.IssuerName)

		if err != nil {
			return reportLines, err
		}

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

	bugMap := make(map[string]bugs.BugData)

	for _, bug := range searchResponse.Bugs {
		bugMap[fmt.Sprintf("%d", bug.Id)] = bug
	}

	// loop over the report lines and fill in the summary from the bug
	for idx, reportLine := range reportLines {
		reportLines[idx].Summary = bugMap[reportLine.Bug].Summary
	}

	return reportLines, nil
}

func renderToHTML(reportLines []ReportLine, file *os.File) {
	w := bufio.NewWriter(file)

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

	for _, reportLine := range reportLines {
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
	typePtr := flag.String("type", "html", "the type of report to generate (options: html)")
	outFilePtr := flag.String("outfile", "report", "the filename of the report to create")

	config.DefineFlags()
	flag.Parse()
	conf := config.GetConfig()

	reportLines, err := GetReportLines(conf, urlPtr)
	if nil != err {
		panic(err)
	}

	f, err := os.Create(*outFilePtr)
	if nil != err {
		panic(err)
	}

	// render the report
	if "HTML" == strings.ToUpper(*typePtr) {
		renderToHTML(reportLines, f)
	} else {
		panic(errors.New("Unrecognized report type"))
	}

	defer f.Close()
}
