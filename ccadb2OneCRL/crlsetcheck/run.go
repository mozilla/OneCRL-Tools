/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Package crlsetcheck reports revoked intermediate certificates in Chrome's
// CRLSet that are neither in OneCRL nor staged for it.
//
// Run writes Slack messages to Config.ReportDir for the caller to post. Each
// run reports every such certificate, so a certificate is reported until it is
// added to OneCRL or its CCADB OneCRL status is set to "Not Applicable".
package crlsetcheck

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gocarina/gocsv"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/crlset"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
)

type Config struct {
	// Where to write Slack messages. If empty, the messages are logged instead.
	ReportDir string
	// If set, check this "crl-set" file rather than fetching the CRLSet from Google.
	CRLSetFile string
}

// FailureFile is the name of the file in Config.ReportDir that Run writes a
// Slack message to if the check fails.
const FailureFile = "crlset-check-failed.txt"

const (
	includedRootsURL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"
	intermediatesURL = "https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV"
	revokedURL       = "https://ccadb.my.salesforce-sites.com/mozilla/PublicIntermediateCertsRevokedWithPEMCSV"
)

var client = &http.Client{Timeout: 5 * time.Minute}

// Run checks the entries in the CRLSet against the OneCRL records that oneCRL
// returns, which should include any records that are staged but not yet
// published.
//
// Run removes any messages that a previous run left in cfg.ReportDir. If the
// check fails, Run writes a message about the failure to FailureFile, as well
// as returning the error.
func Run(cfg Config, oneCRL func() ([]*onecrl.Record, error)) error {
	if err := removeReports(cfg.ReportDir); err != nil {
		return err
	}
	err := run(cfg, oneCRL)
	if err != nil && cfg.ReportDir != "" {
		message := fmt.Sprintf("*ccadb2OneCRL's CRLSet check failed:* %s\n", escape(err.Error()))
		if werr := os.WriteFile(filepath.Join(cfg.ReportDir, FailureFile), []byte(message), 0644); werr != nil {
			log.WithError(werr).Error("failed to write the CRLSet check failure report")
		}
	}
	return err
}

// removeReports removes any messages from reportDir.
func removeReports(reportDir string) error {
	if reportDir == "" {
		return nil
	}
	for _, file := range append(reportFiles(), FailureFile) {
		if err := os.Remove(filepath.Join(reportDir, file)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func run(cfg Config, oneCRL func() ([]*onecrl.Record, error)) error {
	set, err := loadCRLSet(cfg)
	if err != nil {
		return err
	}
	log.WithField("sequence", set.Header.Sequence).
		WithField("parents", len(set.Entries)).
		WithField("serials", set.Count()).
		Info("loaded CRLSet")
	in, err := loadCCADB()
	if err != nil {
		return err
	}
	in.CRLSet = set
	if in.OneCRL, err = oneCRL(); err != nil {
		return errors.Wrap(err, "failed to load OneCRL")
	}
	log.WithField("records", len(in.OneCRL)).Info("loaded OneCRL")
	findings := Check(in)
	for _, f := range findings {
		log.WithField("kind", f.Kind).
			WithField("subject", f.Subject).
			WithField("issuer", f.Issuer).
			WithField("serial", f.Serial).
			WithField("fingerprint", f.Fingerprint).
			WithField("ccadbOneCRLStatus", f.OneCRLStatus).
			Warn(f.Kind.Description())
	}
	log.WithField("count", len(findings)).Info("CRLSet check completed")

	for _, r := range reports {
		message := r.Message(set, findings)
		if message == "" {
			continue
		}
		if cfg.ReportDir == "" {
			log.WithField("message", message).Info("CRLSet check report")
			continue
		}
		if err := os.WriteFile(filepath.Join(cfg.ReportDir, r.File), []byte(message), 0644); err != nil {
			return err
		}
	}
	return nil
}

func loadCRLSet(cfg Config) (*crlset.CRLSet, error) {
	if cfg.CRLSetFile == "" {
		return crlset.Fetch(client)
	}
	b, err := os.ReadFile(cfg.CRLSetFile)
	if err != nil {
		return nil, err
	}
	set, err := crlset.Parse(b)
	return set, errors.Wrap(err, cfg.CRLSetFile)
}

// loadCCADB loads the CCADB reports that Check needs.
func loadCCADB() (*Input, error) {
	type pemRow struct {
		TrustBits string `csv:"Trust Bits"`
		PemInfo   string `csv:"PEM Info"`
	}
	loadCerts := func(url string, keep func(*pemRow) bool) ([]*x509.Certificate, error) {
		rows := make([]*pemRow, 0)
		if err := getCSV(url, &rows); err != nil {
			return nil, err
		}
		certs := make([]*x509.Certificate, 0, len(rows))
		for _, row := range rows {
			if !keep(row) {
				continue
			}
			cert, err := (&ccadb.Certificate{PemInfo: row.PemInfo}).ParseCertificate()
			if err != nil {
				log.WithError(err).WithField("url", url).Warn("failed to parse CCADB certificate")
				continue
			}
			certs = append(certs, cert)
		}
		return certs, nil
	}
	roots, err := loadCerts(includedRootsURL, func(row *pemRow) bool {
		return strings.Contains(row.TrustBits, "Websites")
	})
	if err != nil {
		return nil, err
	}
	intermediates, err := loadCerts(intermediatesURL, func(*pemRow) bool { return true })
	if err != nil {
		return nil, err
	}
	revoked := make([]*ccadb.Certificate, 0)
	if err := getCSV(revokedURL, &revoked); err != nil {
		return nil, err
	}
	log.WithField("roots", len(roots)).
		WithField("intermediates", len(intermediates)).
		WithField("revoked", len(revoked)).
		Info("loaded CCADB reports")
	return &Input{Roots: roots, Intermediates: intermediates, Revoked: revoked}, nil
}

func getCSV(url string, out interface{}) error {
	resp, err := client.Get(url)
	if err != nil {
		return errors.Wrapf(err, "failed to fetch %s", url)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s returned status %d", url, resp.StatusCode)
	}
	return errors.Wrapf(gocsv.Unmarshal(resp.Body, out), "malformed CSV from %s", url)
}
