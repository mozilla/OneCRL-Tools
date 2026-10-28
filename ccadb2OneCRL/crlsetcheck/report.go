/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crlsetcheck

import (
	"fmt"
	"strings"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/crlset"
)

// At most this many findings are listed in a Slack message. All of them are logged.
const maxListed = 20

// A report is a Slack message about some of the findings.
type report struct {
	// The name of the file in Config.ReportDir that the message is written to.
	File string
	// Which findings belong in the message.
	Kinds []Kind
	// The headline, given the number of findings.
	Headline func(n int) string
}

var reports = []report{
	{
		// ccadb2OneCRL starts from the CCADB, so it won't pick these up.
		File:  "revoked-only-in-crlset.txt",
		Kinds: []Kind{CCADBNotRevoked, Undisclosed},
		Headline: func(n int) string {
			return fmt.Sprintf("Chrome's CRLSet revokes %s that the CCADB does not record as revoked", certificates(n))
		},
	},
	{
		// ccadb2OneCRL only stages certificates whose CCADB OneCRL status is
		// "Ready to Add", and stages nothing while a previous change is in review.
		File:  "revoked-in-ccadb.txt",
		Kinds: []Kind{NotInOneCRL},
		Headline: func(n int) string {
			verb := "are"
			if n == 1 {
				verb = "is"
			}
			return fmt.Sprintf("Chrome's CRLSet revokes %s that the CCADB records as revoked but that %s neither in OneCRL nor staged for it",
				certificates(n), verb)
		},
	},
}

func reportFiles() []string {
	files := make([]string, 0, len(reports))
	for _, r := range reports {
		files = append(files, r.File)
	}
	return files
}

func certificates(n int) string {
	if n == 1 {
		return "1 intermediate certificate"
	}
	return fmt.Sprintf("%d intermediate certificates", n)
}

// Message formats the findings that belong in the report as a Slack message
// (in Slack's mrkdwn). It returns "" if there are none.
func (r *report) Message(set *crlset.CRLSet, findings []*Finding) string {
	selected := make([]*Finding, 0)
	for _, f := range findings {
		for _, kind := range r.Kinds {
			if f.Kind == kind {
				selected = append(selected, f)
			}
		}
	}
	if len(selected) == 0 {
		return ""
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "*%s*\n", r.Headline(len(selected)))
	fmt.Fprintf(b, "In CRLSet %d.\n", set.Header.Sequence)
	for i, f := range selected {
		if i == maxListed {
			fmt.Fprintf(b, "…and %d more. See the job log for the full list.\n", len(selected)-maxListed)
			break
		}
		fmt.Fprintf(b, "• %s\n", line(f))
	}
	return b.String()
}

func line(f *Finding) string {
	var link string
	if f.Fingerprint != "" {
		link = fmt.Sprintf("<https://crt.sh/?sha256=%s|%s>", f.Fingerprint, escape(f.Subject))
	} else {
		link = fmt.Sprintf("serial <https://crt.sh/?serial=%s|%s>", f.Serial, f.Serial)
	}
	s := fmt.Sprintf("%s issued by %s", link, escape(f.Issuer))
	if f.CAOwner != "" {
		s += fmt.Sprintf(" (%s)", escape(f.CAOwner))
	}
	switch f.Kind {
	case NotInOneCRL:
		details := []string{"revoked " + escape(f.RevocationDate)}
		if f.ReasonCode != "" {
			details = append(details, escape(f.ReasonCode))
		}
		// ccadb2OneCRL only stages certificates that are "Ready to Add".
		if f.OneCRLStatus != "" {
			details = append(details, fmt.Sprintf("OneCRL status %q", escape(f.OneCRLStatus)))
		} else {
			details = append(details, "no OneCRL status")
		}
		s += ". CCADB: " + strings.Join(details, ", ") + "."
	case CCADBNotRevoked:
		s += ". It is in the CCADB, but not as revoked."
	case Undisclosed:
		s += ". It is not disclosed in the CCADB."
	}
	return s
}

// Slack requires these characters to be escaped in message text.
var escaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func escape(s string) string {
	return escaper.Replace(s)
}
