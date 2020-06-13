/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"encoding/csv"
	"fmt"
	"strings"
	"testing"
)

const example = `"CA Owner","Revocation Status","RFC 5280 Revocation Reason Code","Date of Revocation","OneCRL Status","OneCRL Bug Number","Certificate Serial Number","CA Owner/Certificate Name","Certificate Issuer Common Name","Certificate Issuer Organization","Certificate Subject Common Name","Certificate Subject Organization","SHA-256 Fingerprint","Subject + SPKI SHA256","Valid From [GMT]","Valid To [GMT]","Public Key Algorithm","Signature Hash Algorithm","CRL URL(s)","Alternate CRL","Comments","PEM Info"
"SECOM Trust Systems CO., LTD.","Revoked","","2020 Jun 09","Ready to Add","","22B9B0D6","NII Open Domain Code Signing CA - G2","","SECOM Trust Systems CO.,LTD.","NII Open Domain Code Signing CA - G2","National Institute of Informatics","7F9D66A7964E27654B7677464C24A786548C9774504C15C38449B4419FF38B5F","9235DB3B5C9377AF4AE4F4FF86DABBD10C9BC7A0C52720E0D0646306436D20B1","2015 Feb 26","2025 Feb 26","RSA 2048 bits","SHA256WithRSA","http://repository.secomtrust.net/SC-Root2/SCRoot2CRL.crl","","","'-----BEGIN CERTIFICATE-----
MIIEoDCCA4igAwIBAgIEIrmw1jANBgkqhkiG9w0BAQsFADBdMQswCQYDVQQGEwJK
UDElMCMGA1UEChMcU0VDT00gVHJ1c3QgU3lzdGVtcyBDTy4sTFRELjEnMCUGA1UE
CxMeU2VjdXJpdHkgQ29tbXVuaWNhdGlvbiBSb290Q0EyMB4XDTE1MDIyNjA2Mjk1
MloXDTI1MDIyNjA2Mjk1MlowejELMAkGA1UEBhMCSlAxEDAOBgNVBAcTB0FjYWRl
bWUxKjAoBgNVBAoTIU5hdGlvbmFsIEluc3RpdHV0ZSBvZiBJbmZvcm1hdGljczEt
MCsGA1UEAxMkTklJIE9wZW4gRG9tYWluIENvZGUgU2lnbmluZyBDQSAtIEcyMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkx32+IsEfNQfVcAkSykGar/y
YdGyu/qmcZ8UpoNdl57H1mrWRkv8Kt5r7fK890yy8v2x/2qsCRNO+D0NZKp3Vkoq
QbHcqG5/THAs78/VOkLylrd6jZzaVOKIAn9VYShALIql8YNnMYVOHni3cCQZsbH/
b8G7UDiC+Wu8xFBULb6Oh9lJ1OCRubCMX/sznr8A98XD4aoYZCP1NYO5tSV/oh3I
5nEBAjNgNWcI+dJtR9vC6rXpekr0E/x1+1x0DFXraOEhmYVuWjOSAS8bkWCJB10O
hR74a2lE3nywF99vcSde4JMj5ZD/w6IJ8ubpsc90ENJ6hmlwiSKiVQYE8TDAUwID
AQABo4IBSTCCAUUwHQYDVR0OBBYEFFTXON4auUnL/7soY+cnH6teKiRHMB8GA1Ud
IwQYMBaAFAqFqXdlBZh8QIH4D5csOPEK7DzPMBIGA1UdEwEB/wQIMAYBAf8CAQAw
DgYDVR0PAQH/BAQDAgEGMEkGA1UdHwRCMEAwPqA8oDqGOGh0dHA6Ly9yZXBvc2l0
b3J5LnNlY29tdHJ1c3QubmV0L1NDLVJvb3QyL1NDUm9vdDJDUkwuY3JsMFIGA1Ud
IARLMEkwRwYKKoMIjJsbZIcFBDA5MDcGCCsGAQUFBwIBFitodHRwczovL3JlcG9z
aXRvcnkuc2Vjb210cnVzdC5uZXQvU0MtUm9vdDIvMEAGCCsGAQUFBwEBBDQwMjAw
BggrBgEFBQcwAYYkaHR0cDovL3Njcm9vdGNhMi5vY3NwLnNlY29tdHJ1c3QubmV0
MA0GCSqGSIb3DQEBCwUAA4IBAQATlI35Ka0BZxtd/5CoLLs94ucZ0NrUPDS3zRMJ
lBEbEKr2+aU49jp8Yq0TRyvbgQ/eowDoeHtZVeJEhu7gAMriVCvTyIyuH+Y78CyA
JmffM5ePGIyENhSFTcUdRsrlwo+1CkYaZaQw9/36BexYWGthyGFIvoG0osS92feW
2r6Sett9cH0AKQ/8ChAWDkQtu5YdR3iGIU3U9woM6B6mkHw7uw7QjwTU//yG5tiy
6VY1TzqplPQ62dp1jFtN9KTRkJXr8FVvmRYirY316uvm6I6L/eSvgJZeusEQqqr4
QN793ae1wTx52mqE+Rnm1T/mXdNxEilUZ8DCZm5a1brzypBU
-----END CERTIFICATE-----'"`

func TestSmoke(t *testing.T) {
	certs, err := FromReader(strings.NewReader(example))
	if err != nil {
		panic(err)
	}
	if len(certs) != 1 {
		t.Fatalf("unexpected number of parsed entried. Wanted 1, got %d", len(certs))
	}
	fmt.Printf("%v", certs[0].PemInfo)
}

func TestBadHeader(t *testing.T) {
	r := csv.NewReader(strings.NewReader(example))
	h, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	header := make(map[string]int)
	for i, v := range h {
		header[v] = i
	}
	record, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		t.Log(fmt.Sprintf("%s: %s", k, record[v]))
	}
}

func TestCertificate_ParseCertificate(t *testing.T) {
	certs, err := FromReader(strings.NewReader(example))
	if err != nil {
		panic(err)
	}
	if len(certs) != 1 {
		t.Fatalf("unexpected number of parsed entried. Wanted 1, got %d", len(certs))
	}
	cert := certs[0]
	_, err = cert.ParseCertificate()
	if err != nil {
		t.Fatal(err)
	}
}
