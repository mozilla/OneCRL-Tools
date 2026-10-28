/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crlsetcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
)

func TestRunFailure(t *testing.T) {
	dir := t.TempDir()
	for _, file := range reportFiles() {
		if err := os.WriteFile(filepath.Join(dir, file), []byte("stale"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	oneCRL := func() ([]*onecrl.Record, error) {
		t.Error("OneCRL should not be loaded")
		return nil, nil
	}
	missing := filepath.Join(dir, "missing-crl-set")
	if err := Run(Config{ReportDir: dir, CRLSetFile: missing}, oneCRL); err == nil {
		t.Fatal("expected an error for a missing CRLSet file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != FailureFile {
		t.Fatalf("expected only %s, got %v", FailureFile, entries)
	}
	b, err := os.ReadFile(filepath.Join(dir, FailureFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "*ccadb2OneCRL's CRLSet check failed:* ") || !strings.Contains(string(b), "missing-crl-set") {
		t.Errorf("unexpected failure report %q", b)
	}
}
