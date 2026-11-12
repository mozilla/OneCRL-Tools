/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Package crlset fetches and parses Chrome's CRLSet.
//
// A CRLSet is a list of revoked serial numbers keyed by the SHA-256 hash of
// the issuer's SubjectPublicKeyInfo. Chrome distributes it as a component
// through the Omaha update protocol. The component is a CRX3 file which
// wraps a zip archive which contains a file named "crl-set".
//
// The "crl-set" file is formatted as follows:
//
//	uint16 header_length (little endian)
//	byte   header[header_length] (JSON)
//	repeated {
//	    byte   parent_spki_sha256[32]
//	    uint32 num_serials (little endian)
//	    repeated num_serials times {
//	        uint8 serial_length
//	        byte  serial[serial_length]
//	    }
//	}
//
// Serial numbers in a CRLSet do not have the leading zero byte that
// DER requires when the high bit of the first byte is set.
package crlset

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

// AppID is the Omaha application ID of the CRLSet component.
const AppID = "hfnkpimlhhgieaddgfemjhofmfblmnib"

const omahaURL = "https://update.googleapis.com/service/update2/json"

// Omaha assigns clients to cohorts, and some cohorts (e.g. "Auto androidlowmem")
// receive a heavily truncated CRLSet. Claiming to be a desktop Chrome gets us
// the "Auto full" cohort, which is what desktop Chrome installations receive.
const omahaRequest = `{"request":{"protocol":"3.1","acceptformat":"crx3","dedup":"cr","ismachine":false,
"os":{"platform":"Linux","arch":"x86_64","version":"6.12"},"arch":"x64","nacl_arch":"x86-64",
"prodversion":"142.0.7444.0","updaterversion":"142.0.7444.0","prodchannel":"stable","lang":"en-US",
"app":[{"appid":"` + AppID + `","version":"0.0.0.0","enabled":true,"updatecheck":{},"ping":{"r":-2}}]}}`

type Header struct {
	Version     int
	ContentType string
	Sequence    int
	NumParents  int
}

type CRLSet struct {
	Header Header
	// Revoked serial numbers (without leading zero bytes) keyed by the
	// SHA-256 hash of the issuer's SubjectPublicKeyInfo.
	Entries map[[32]byte][][]byte
}

// Parse parses the contents of a "crl-set" file.
func Parse(b []byte) (*CRLSet, error) {
	if len(b) < 2 {
		return nil, errors.New("crlset: truncated header length")
	}
	headerLen := int(binary.LittleEndian.Uint16(b))
	b = b[2:]
	if len(b) < headerLen {
		return nil, errors.New("crlset: truncated header")
	}
	set := &CRLSet{Entries: make(map[[32]byte][][]byte)}
	if err := json.Unmarshal(b[:headerLen], &set.Header); err != nil {
		return nil, errors.Wrap(err, "crlset: malformed header")
	}
	if set.Header.ContentType != "CRLSet" {
		return nil, fmt.Errorf("crlset: unexpected content type %q", set.Header.ContentType)
	}
	b = b[headerLen:]
	for len(b) > 0 {
		if len(b) < 36 {
			return nil, errors.New("crlset: truncated entry")
		}
		var parent [32]byte
		copy(parent[:], b[:32])
		numSerials := binary.LittleEndian.Uint32(b[32:36])
		b = b[36:]
		serials := make([][]byte, 0, numSerials)
		for i := uint32(0); i < numSerials; i++ {
			if len(b) < 1 || len(b) < 1+int(b[0]) {
				return nil, errors.New("crlset: truncated serial")
			}
			serials = append(serials, NormalizeSerial(b[1:1+int(b[0])]))
			b = b[1+int(b[0]):]
		}
		set.Entries[parent] = append(set.Entries[parent], serials...)
	}
	return set, nil
}

// NormalizeSerial strips leading zero bytes so that serial numbers from
// the CRLSet can be compared with DER encoded serial numbers.
func NormalizeSerial(serial []byte) []byte {
	for len(serial) > 1 && serial[0] == 0 {
		serial = serial[1:]
	}
	return serial
}

// Count returns the number of revoked serial numbers in the CRLSet.
func (s *CRLSet) Count() int {
	n := 0
	for _, serials := range s.Entries {
		n += len(serials)
	}
	return n
}

type omahaResponse struct {
	Response struct {
		App []struct {
			AppID       string `json:"appid"`
			Status      string `json:"status"`
			CohortName  string `json:"cohortname"`
			UpdateCheck struct {
				Status string `json:"status"`
				URLs   struct {
					URL []struct {
						Codebase string `json:"codebase"`
					} `json:"url"`
				} `json:"urls"`
				Manifest struct {
					Version  string `json:"version"`
					Packages struct {
						Package []struct {
							Name       string `json:"name"`
							HashSHA256 string `json:"hash_sha256"`
						} `json:"package"`
					} `json:"packages"`
				} `json:"manifest"`
			} `json:"updatecheck"`
		} `json:"app"`
	} `json:"response"`
}

// Fetch downloads the current CRLSet from Google's update servers.
//
// The integrity of the download is checked against the SHA-256 hash in the
// (HTTPS) Omaha response. The CRX3 signature is not verified.
func Fetch(client *http.Client) (*CRLSet, error) {
	req, err := http.NewRequest(http.MethodPost, omahaURL, strings.NewReader(omahaRequest))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Goog-Update-AppId", AppID)
	req.Header.Set("X-Goog-Update-Interactivity", "bg")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "crlset: omaha request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crlset: omaha returned status %d", resp.StatusCode)
	}
	// The response is prefixed with ")]}'" to prevent JSON hijacking.
	body = bytes.TrimPrefix(body, []byte(")]}'"))
	var omaha omahaResponse
	if err := json.Unmarshal(body, &omaha); err != nil {
		return nil, errors.Wrap(err, "crlset: malformed omaha response")
	}
	if len(omaha.Response.App) != 1 || omaha.Response.App[0].AppID != AppID {
		return nil, errors.New("crlset: omaha response does not describe the CRLSet component")
	}
	app := omaha.Response.App[0]
	if app.Status != "ok" || app.UpdateCheck.Status != "ok" {
		return nil, fmt.Errorf("crlset: omaha update check failed: %s/%s", app.Status, app.UpdateCheck.Status)
	}
	if strings.Contains(strings.ToLower(app.CohortName), "lowmem") {
		return nil, fmt.Errorf("crlset: omaha assigned us to the truncated %q cohort", app.CohortName)
	}
	packages := app.UpdateCheck.Manifest.Packages.Package
	if len(packages) != 1 {
		return nil, fmt.Errorf("crlset: expected one package, got %d", len(packages))
	}
	expectedHash, err := hex.DecodeString(packages[0].HashSHA256)
	if err != nil || len(expectedHash) != sha256.Size {
		return nil, errors.New("crlset: malformed package hash")
	}
	var codebase string
	for _, url := range app.UpdateCheck.URLs.URL {
		if strings.HasPrefix(url.Codebase, "https://") {
			codebase = url.Codebase
			break
		}
	}
	if codebase == "" {
		return nil, errors.New("crlset: no https download URL in omaha response")
	}
	crxResp, err := client.Get(codebase + packages[0].Name)
	if err != nil {
		return nil, errors.Wrap(err, "crlset: download failed")
	}
	defer crxResp.Body.Close()
	crx, err := io.ReadAll(crxResp.Body)
	if err != nil {
		return nil, err
	}
	if crxResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crlset: download returned status %d", crxResp.StatusCode)
	}
	if hash := sha256.Sum256(crx); !bytes.Equal(hash[:], expectedHash) {
		return nil, errors.New("crlset: downloaded package does not match the hash in the omaha response")
	}
	return FromCRX3(crx)
}

// FromCRX3 extracts and parses the "crl-set" file from a CRX3 package.
func FromCRX3(crx []byte) (*CRLSet, error) {
	archive, err := unwrapCRX3(crx)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, errors.Wrap(err, "crlset: malformed zip archive")
	}
	for _, f := range zr.File {
		if f.Name != "crl-set" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}
		return Parse(b)
	}
	return nil, errors.New("crlset: no crl-set file in package")
}

// A CRX3 file is the magic "Cr24", a uint32 version (3), a uint32 header
// length, a protobuf header of that length, and then a zip archive.
func unwrapCRX3(crx []byte) ([]byte, error) {
	if len(crx) < 12 || string(crx[:4]) != "Cr24" {
		return nil, errors.New("crlset: not a CRX file")
	}
	if version := binary.LittleEndian.Uint32(crx[4:8]); version != 3 {
		return nil, fmt.Errorf("crlset: unsupported CRX version %d", version)
	}
	headerLen := binary.LittleEndian.Uint32(crx[8:12])
	if uint64(len(crx)) < 12+uint64(headerLen) {
		return nil, errors.New("crlset: truncated CRX header")
	}
	return crx[12+headerLen:], nil
}
