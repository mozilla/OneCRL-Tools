/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crlsetcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/crlset"
)

var testCRLSet = &crlset.CRLSet{Header: crlset.Header{Sequence: 10900}}

func messages(findings []*Finding) map[string]string {
	out := make(map[string]string)
	for _, r := range reports {
		if m := r.Message(testCRLSet, findings); m != "" {
			out[r.File] = m
		}
	}
	return out
}

func TestReports(t *testing.T) {
	findings := []*Finding{
		{Kind: CCADBNotRevoked, Subject: "CN=B", Issuer: "CN=Root", Serial: "02", Fingerprint: "bb"},
		{Kind: NotInOneCRL, Subject: "CN=C", Issuer: "CN=Root", Serial: "03", Fingerprint: "cc", RevocationDate: "2026 Oct 22"},
		{
			Kind: NotInOneCRL, Subject: "CN=A & B <Intermediate>", Issuer: "CN=Root", Serial: "01",
			Fingerprint: "aa", CAOwner: "Example CA", RevocationDate: "2026 Nov 10",
			ReasonCode: "(1) keyCompromise", OneCRLStatus: "Ready to Add",
		},
		{Kind: Undisclosed, Issuer: "CN=Root", Serial: "99"},
	}
	expected := map[string]string{
		"revoked-only-in-crlset.txt": `*Chrome's CRLSet revokes 2 intermediate certificates that the CCADB does not record as revoked*
In CRLSet 10900.
• <https://crt.sh/?sha256=bb|CN=B> issued by CN=Root. It is in the CCADB, but not as revoked.
• serial <https://crt.sh/?serial=99|99> issued by CN=Root. It is not disclosed in the CCADB.
`,
		"revoked-in-ccadb.txt": `*Chrome's CRLSet revokes 2 intermediate certificates that the CCADB records as revoked but that are neither in OneCRL nor staged for it*
In CRLSet 10900.
• <https://crt.sh/?sha256=cc|CN=C> issued by CN=Root. CCADB: revoked 2026 Oct 22, no OneCRL status.
• <https://crt.sh/?sha256=aa|CN=A &amp; B &lt;Intermediate&gt;> issued by CN=Root (Example CA). CCADB: revoked 2026 Nov 10, (1) keyCompromise, OneCRL status "Ready to Add".
`,
	}
	got := messages(findings)
	if len(got) != len(expected) {
		t.Errorf("expected %d messages, got %d", len(expected), len(got))
	}
	for file, want := range expected {
		if got[file] != want {
			t.Errorf("unexpected %s:\n%s", file, got[file])
		}
	}

	// Each kind of finding is in exactly one message.
	for _, kind := range []Kind{NotInOneCRL, CCADBNotRevoked, Undisclosed} {
		if got := messages([]*Finding{{Kind: kind}}); len(got) != 1 {
			t.Errorf("%s is in %d messages", kind, len(got))
		}
	}
	if got := messages(nil); len(got) != 0 {
		t.Errorf("expected no messages without findings, got %v", got)
	}
}

func TestReportTruncated(t *testing.T) {
	many := make([]*Finding, maxListed+5)
	for i := range many {
		many[i] = &Finding{Kind: Undisclosed, Issuer: "CN=Root", Serial: fmt.Sprintf("%02x", i)}
	}
	got := messages(many)["revoked-only-in-crlset.txt"]
	if n := strings.Count(got, "\n• "); n != maxListed {
		t.Errorf("expected %d listed findings, got %d", maxListed, n)
	}
	if !strings.Contains(got, "…and 5 more.") {
		t.Errorf("expected a count of the unlisted findings:\n%s", got)
	}
}
