---
title: "Report"
date: 2018-01-01T14:11:05-07:00
draft: true
---

<!-- This Source Code Form is subject to the terms of the Mozilla Public -->
<!-- License, v. 2.0. If a copy of the MPL was not distributed with this -->
<!-- file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Recommendation

I recommend that,

* __Pending the work outlined in the [Work to be Done](#work-to-be-done) section, as well as review of the discovered semantic differences, that the CCADB be wiped and repopulated using the data parsed from each certificate's PEM by the TLS Observatory__.
* Other than the work that has been done to push for bugfixes in the Golang X.509 package, that the TLS Observatory's output remain otherwise unchanged.
* That the CCADB's schema remain unchanged.
* That the CCADB accepts string values from the TLS Observatory unaltered.
	* That is, that the CCADB accept the formatting and enum values used by the Golang crypto/x509 package.
* That the CCADB perform transformations on the data provided by the TLS Observatory only when necessary.
	* That when the CCADB is provided with a JSON array value, that it transform it into a well formed and properly escaped CSV string.
	* That when the CCADB is provided with an aggregate type (E.G. `Public Key Algorithm`), that the CCADB must construct a string that is directly tracable to the original value generate by the TLS Observatory.
	* That when the CCADB generates a Distinguished Name, or Relative Distinguished Name, that it strictly adhere to [RFC 1779](https://tools.ietf.org/html/rfc1779).
* That all string transformations and formats that are stored in the CCADB target *machine readbility* over human readability.
	* That all formatting that is to be done to facilitate human readability be done in the presentation layer in Salesforce, rather than being persisted as the single source of truth on disk.

## Work to be Done

* TLS Observatory
	* Vendor a pre-release version of [Golang 1.11](https://github.com/golang/go/milestone/62).
        * This should be closed by the merging and deployment of [pull request 288](https://github.com/mozilla/tls-observatory/pull/288) in the TLS Observatory.
		* This will correct [issue 271](https://github.com/mozilla/tls-observatory/issues/271) in the TLS Observatory.
		* This will correct [issue 281](https://github.com/mozilla/tls-observatory/issues/281) in the TLS Observatory.
	    * This will correct [issue 283](https://github.com/mozilla/tls-observatory/issues/283) in the TLS Observatory.
    * Make an addition to the TLS Observatory output called `ExtendedKeyUsageOID` which is to be a []oid.
        * This will correct [issue 338](https://github.com/mozilla/tls-observatory/issues/338)
    * Implement the fix proposed in [issue 291](https://github.com/mozilla/tls-observatory/issues/291) to fix the issue wherein [the TLS Observatory is missing leading zeroes from some certificates](#certificate-serial-number-intermediate-fname-certificateserialnumber)
    * Implement the fix proposed in [issue 289](https://github.com/mozilla/tls-observatory/issues/289) to fix the issue wherein [the TLS Observatory is missing EKUs for some certificates](#extended-key-usage-intermediate-fname-extendedkeyusage)

* CCADB
	* A data insertion pipeline should be implemented for the CCADB.
		* Direct insertion of arbitrary values should be disallowed.
		* Insertion should be done by providing a PEM, with which the CCADB will consult the TLS Observatory for parsing results.
	* The following transformations, outlined in their original sections, must be implemented as a part of a CCADB insertion pipeline.
        * Intermediate
    		* [Filter LDAP address and parse CRL URL(s) into a CSV.](#crl-url-s-intermediate-fname-crlurl-s)
    		* [Properly form Organizational Unit as a CSV.](#certificate-issuer-organizational-unit-intermediate-fname-certificateissuerorganizationalunit)
    		* [Properly form EKUs as a CSV.](#extended-key-usage-intermediate-fname-extendedkeyusage)
    		* [Perform a mapping of the TLS Observatory's Public Key Algorithm into a string.](#public-key-algorithm-intermediate-fname-publickeyalgorithm)
    		* [Truncate ValidFrom and ValidTo to the lower resolution time format](#valid-from-gmt-intermediate-fname-validfromgmt)
        * Root
            * [Properly form Certificate Issuer Organizational Unit as a CSV.](#certificate-issuer-organizational-unit-root-fname-certificateissuerorganizationalunit)
            * [Properly form Certificate Subject Organizational Unit as a CSV.](#certificate-subject-organization-unit-root-fname-certificatesubjectorganizationunit)
            * [Perform a mapping of the TLS Observatory's Public Key Algorithm into a string.](#public-key-algorithm-root-fname-publickeyalgorithm)
            * [Properly form Subject as a Distinguished Name as per RFC 1779.](#subject-root-fname-subject)
            * [Truncate ValidFrom and ValidTo to the lower resolution time format](#valid-from-gmt-root-fname-validfromgmt)
	* A one-off script should be implemented to allow for the mass insertion of certificates using the above pipeline.
	* This script should be executed against a sandbox environment.
        * This sandbox environment should undergo an analysis similar to the one used to create this document.
        * Discovered issues must be corrected and the analysis regenerated, iteratively.
        * Upon acceptance of the analysis of the sandbox environment, the production environment for the CCADB may be migrated.

* Execution

Below is an example workflow for the migration of the CCADB to using the TLS Observatory as the single source of truth parsing tool.

![](/images/ccadb_flow.png)

# Query the TLS Observatory

The TLS Observatory can be queried to parse a certificate at `https://tls-observatory.services.mozilla.com/api/v1/certificate`. This endpoint accepts either a `GET` or a `POST`

## POST

The TLS Observatory accepts the content of a well formed PEM. If this PEM is not cached within the TLS Observatory, then the PEM will be parsed completey, cached, and the parse result returned. If this PEM is cached, then the cached results are returned.

> Example cURL

```bash
curl -X POST \
-H "Content-Type: multipart/form-data" \
-F "certificate=@test.crt" \
https://tls-observatory.services.mozilla.com/api/v1/certificate
```

## GET

The TLS Observatory can accept the SHA256 of a certificate as a query paramter if that certificate has already been parsed by at least one call to the above `POST` endpoint. The SHA256 must not be colon delimited. It can be either upper or lower case.

> Example cURL

```bash
curl -X GET \
https://tls-observatory.services.mozilla.com/api/v1/certificate\
?sha256=9BC4F171FF9AA224F00C799E80490E31010E3475A08FE64DC9A9C4192EB0C0B1
```

## Output
> Example Output

```json
{
    "Raw": "MIIGTDCCBTSgAwIBAgIBDDANBgkqhkiG9w0BAQUFADB/MQswCQYDVQQGEwJFVTEnMCUGA1UEChMeQUMgQ2FtZXJmaXJtYSBTQSBDSUYgQTgyNzQzMjg3MSMwIQYDVQQLExpodHRwOi8vd3d3LmNoYW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMgb2YgQ29tbWVyY2UgUm9vdDAeFw0wOTAxMjAxMDIwMTlaFw0xOTAxMTgxMDIwMTlaMIHtMQswCQYDVQQGEwJFUzEiMCAGCSqGSIb3DQEJARYTaW5mb0BjYW1lcmZpcm1hLmNvbTFDMEEGA1UEBxM6TWFkcmlkIChzZWUgY3VycmVudCBhZGRyZXNzIGF0IHd3dy5jYW1lcmZpcm1hLmNvbS9hZGRyZXNzKTESMBAGA1UEBRMJQTgyNzQzMjg3MSIwIAYDVQQLExlodHRwOi8vd3d3LmNhbWVyZmlybWEuY29tMRkwFwYDVQQKExBBQyBDYW1lcmZpcm1hIFNBMSIwIAYDVQQDExlBQyBDYW1lcmZpcm1hIENvZGVzaWduIHYyMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAyNwx4WbAIQBcJThZtBE6N9ccwdpjuZ0GyJxkPWmjNRaCDSkobnmbUt5LKshzKIX/wovAjFcn71XNa4NY6DPgXHteg5Ff62AsMIbudu/cdsAVUSRJF/+lgVbBQOtxS8qMesNPKoD/cL24z3esDqhR1AxtJ2WhdfTmI0SK6EHbGMHJzMrxsvJ7x5sOxU7yHDF3heF5apJRsyAA/hU1kpjuuUAgmkDhQSod6H+fLyUC2uu+0Ka93C2h6CB5IppZkOJ42E9jtmJgOI9ZOnxMV2HvvrNb1SY8i36DPHGmPCEhGjCn2ezuDCoeQP1LLc22Iea05104BxusEBkOjVES7npqlwIBA6OCAmQwggJgMBIGA1UdEwEB/wQIMAYBAf8CAQIwbgYDVR0fBGcwZTAwoC6gLIYqaHR0cDovL2NybC5jYW1lcmZpcm1hLmNvbS9jaGFtYmVyc3Jvb3QuY3JsMDGgL6AthitodHRwOi8vY3JsMS5jYW1lcmZpcm1hLmNvbS9jaGFtYmVyc3Jvb3QuY3JsMB0GA1UdDgQWBBRpGpRyoNGW/z1WKtj+K0cYFZ2w7jCBqwYDVR0jBIGjMIGggBTjlPWxTenboSlbV4tNdgZ24dGiiqGBhKSBgTB/MQswCQYDVQQGEwJFVTEnMCUGA1UEChMeQUMgQ2FtZXJmaXJtYSBTQSBDSUYgQTgyNzQzMjg3MSMwIQYDVQQLExpodHRwOi8vd3d3LmNoYW1iZXJzaWduLm9yZzEiMCAGA1UEAxMZQ2hhbWJlcnMgb2YgQ29tbWVyY2UgUm9vdIIBADB1BggrBgEFBQcBAQRpMGcwPQYIKwYBBQUHMAKGMWh0dHA6Ly93d3cuY2FtZXJmaXJtYS5jb20vY2VydHMvUk9PVC1DSEFNQkVSUy5jcnQwJgYIKwYBBQUHMAGGGmh0dHA6Ly9vY3NwLmNhbWVyZmlybWEuY29tMA4GA1UdDwEB/wQEAwIBBjAeBgNVHREEFzAVgRNpbmZvQGNhbWVyZmlybWEuY29tMCcGA1UdEgQgMB6BHGNoYW1iZXJzcm9vdEBjaGFtYmVyc2lnbi5vcmcwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHA6Ly9wb2xpY3kuY2FtZXJmaXJtYS5jb20wDQYJKoZIhvcNAQEFBQADggEBADOSqMcVWLnxmZPaWwZlwhnChTwoICkDCiZMrwGEcRHDy+XpcOm9LwjHABoEe1RKSefF+KrpGAmYNLy6TpfWvJCemqw0KBpzwKFo8eKjc4pHp/RHa+Oq5i0F090drej2IoLpQwzHEpd9Haj0KxSS/e6AZR7FbBykeajt1L8TwptJBJMrEhY6Ov0bsupZweMTbSGVhZDYn3Wau482XnZ1jHvrjA93lTcCpNZoqUxRnLME0qeI+b49MKOBILCU3JsVqWd6+eilbeJnqI6B7plxn1K/8ZN68fnlVULGniLe4uG7+gzqD4AmWxSyk0FzyggVxtTKx6S/u3BxY9Y/GoPEsf0=",
    "ca": true,
    "ciscoUmbrellaRank": 2147483647,
    "hashes": {
        "pin-sha256": "DOXSaFtKlzmX4cdaIp2lgUKB8JyfkKnogjN6OpCDf9M=",
        "sha1": "7240558E1CE4A0C77D4072625596D6749AF9D797",
        "sha256": "9BC4F171FF9AA224F00C799E80490E31010E3475A08FE64DC9A9C4192EB0C0B1",
        "sha256_subject_spki": "BD1B46C7C5253FE92B574FEADF9F555E6E093FA44D652BA8F56549F382B0FBAA"
    },
    "id": 25095119,
    "issuer": {
        "c": [
            "EU"
        ],
        "CN": "Chambers of Commerce Root",
        "o": [
            "AC Camerfirma SA CIF A82743287"
        ],
        "ou": [
            "http://www.chambersign.org"
        ]
    },
    "key": {
        "alg": "RSA",
        "exponent": 3,
        "curve": "",
        "size": 2048
    },
    "lastSeenTimestamp": "2017-06-27T21:26:31.524236Z",
    "serialNumber": "0C",
    "SignatureAlgorithm": "SHA1WithRSA",
    "subject": {
        "c": [
            "ES"
        ],
        "CN": "AC Camerfirma Codesign v2",
        "o": [
            "AC Camerfirma SA"
        ],
        "ou": [
            "http://www.camerfirma.com"
        ]
    },
    "validationInfo": {
        "Android": {
            "isValid": false
        },
        "Apple": {
            "isValid": true
        },
        "Microsoft": {
            "isValid": false
        },
        "Mozilla": {
            "isValid": false
        },
        "Ubuntu": {
            "isValid": false
        }
    },
    "validity": {
        "notAfter": "2019-01-18T10:20:19Z",
        "notBefore": "2009-01-20T10:20:19Z"
    },
    "version": 3,
    "x509v3BasicConstraints": "Critical",
    "x509v3Extensions": {
        "authorityKeyId": "45T1sU3p26EpW1eLTXYGduHRooo=",
        "crlDistributionPoint": [
            "http://crl.camerfirma.com/chambersroot.crl",
            "http://crl1.camerfirma.com/chambersroot.crl"
        ],
        "isTechnicallyConstrained": false,
        "keyUsage": [
            "Certificate Sign",
            "CRL Sign"
        ],
        "policyIdentifiers": [
            "2.5.29.32.0"
        ],
        "subjectAlternativeName": [],
        "subjectKeyId": "aRqUcqDRlv89VirY/itHGBWdsO4="
    }
}
```

# Unparsable Certificates

## Invalid Character

The following certificates suffer from [issue 271](https://github.com/mozilla/tls-observatory/issues/271) in the TLS Observatory.

- [D8D7627D0F5D0AD09155B2C9347307925EF3E7F6364F231969C0D2E4C71962F0](https://crt.sh/?q=D8D7627D0F5D0AD09155B2C9347307925EF3E7F6364F231969C0D2E4C71962F0)
- [3B8812E6F851B6F933DC23ED764082FB5F50DE3C2DDDEBCC9CA240B7ACACE4D1](https://crt.sh/?q=3B8812E6F851B6F933DC23ED764082FB5F50DE3C2DDDEBCC9CA240B7ACACE4D1)
- [DB89314466DE24D66551105FC1D381D66D6D9139E820531C298954654C3DC978](https://crt.sh/?q=DB89314466DE24D66551105FC1D381D66D6D9139E820531C298954654C3DC978)

## Unhandled Critical Extension

The following certificates suffer from [issue 281](https://github.com/mozilla/tls-observatory/issues/281) in the TLS Observatory.

- [F85C48B1363A02E29A7B5A45250CC6050F9579338EA3E6AE76F0B3611DEDC0F2](https://crt.sh/?q=F85C48B1363A02E29A7B5A45250CC6050F9579338EA3E6AE76F0B3611DEDC0F2)
- [CF89A41DFEE5F71740DEF602735DDBF1DEBE0CB816D73980D9A583C5881CE778](https://crt.sh/?q=CF89A41DFEE5F71740DEF602735DDBF1DEBE0CB816D73980D9A583C5881CE778)
- [0C3B69672EBABE1F96CAF3CBE598F7747C01F78014AF651191950D673FD91784](https://crt.sh/?q=0C3B69672EBABE1F96CAF3CBE598F7747C01F78014AF651191950D673FD91784)
- [F490F7A7F052F7B130268FCB2BE19A4132C8B1007F09D606685927122EE7A83C](https://crt.sh/?q=F490F7A7F052F7B130268FCB2BE19A4132C8B1007F09D606685927122EE7A83C)
- [BCBD04D4AED962C9D25AFE0CFAF8638CE1431652988EC5217329E7559AC3C671](https://crt.sh/?q=BCBD04D4AED962C9D25AFE0CFAF8638CE1431652988EC5217329E7559AC3C671)
- [30EC1942A183556C4F938167B481F5AEDCE4D1C4EE9F3BFFBD75CA76035FD81C](https://crt.sh/?q=30EC1942A183556C4F938167B481F5AEDCE4D1C4EE9F3BFFBD75CA76035FD81C)
- [3025E05437517139872114F9C81B340E79F4D8F33D5DC069B01F433492C7EBED](https://crt.sh/?q=3025E05437517139872114F9C81B340E79F4D8F33D5DC069B01F433492C7EBED)
- [14165D8E08D40CD6B479108725548B1A08016FDC2262267B82A0BC09D8931056](https://crt.sh/?q=14165D8E08D40CD6B479108725548B1A08016FDC2262267B82A0BC09D8931056)
- [740D5E17B4597635B5E1594FBA02C2B6D07F2E4731A5A91091E7044A817DBDB1](https://crt.sh/?q=740D5E17B4597635B5E1594FBA02C2B6D07F2E4731A5A91091E7044A817DBDB1)

## Empty CCADB Entry
> The following entries in the CCADB have no information other than some name fields.

```json
[
{
    "Auditor": "",
    "Audits Same As Parent": "",
    "BR Audit": "",
    "CA Owner": "IdenTrust",
    "CP/CPS Same As Parent": "",
    "CRL URL(s)": "",
    "Certificate ID": "",
    "Certificate Issuer Common Name": "",
    "Certificate Issuer Organization": "",
    "Certificate Issuer Organizational Unit": "",
    "Certificate Name": "IdenTrust",
    "Certificate Policy (CP)": "",
    "Certificate Serial Number": "",
    "Certificate Subject Common Name": "",
    "Certificate Subject Organization": "",
    "Certification Practice Statement (CPS)": "",
    "Comments": "",
    "Extended Key Usage": "",
    "Key Usage": "",
    "Management Assertions By": "",
    "PEM Info": "",
    "Parent Name": "DST Root CA X3",
    "Public Key Algorithm": "",
    "SHA-1 Fingerprint": "",
    "SHA-256 Fingerprint": "",
    "Signature Hash Algorithm": "",
    "Standard Audit": "",
    "Standard Audit Statement Dt": "",
    "Technically Constrained": "0",
    "Valid From [GMT]": "",
    "Valid To [GMT]": ""
},
{
    "Auditor": "",
    "Audits Same As Parent": "",
    "BR Audit": "",
    "CA Owner": "IdenTrust",
    "CP/CPS Same As Parent": "",
    "CRL URL(s)": "",
    "Certificate ID": "",
    "Certificate Issuer Common Name": "",
    "Certificate Issuer Organization": "",
    "Certificate Issuer Organizational Unit": "",
    "Certificate Name": "Let's Encrypt Authority X3",
    "Certificate Policy (CP)": "",
    "Certificate Serial Number": "",
    "Certificate Subject Common Name": "",
    "Certificate Subject Organization": "",
    "Certification Practice Statement (CPS)": "",
    "Comments": "",
    "Extended Key Usage": "",
    "Key Usage": "",
    "Management Assertions By": "",
    "PEM Info": "",
    "Parent Name": "Let's Encrypt Authority X3",
    "Public Key Algorithm": "",
    "SHA-1 Fingerprint": "",
    "SHA-256 Fingerprint": "",
    "Signature Hash Algorithm": "",
    "Standard Audit": "",
    "Standard Audit Statement Dt": "",
    "Technically Constrained": "false",
    "Valid From [GMT]": "",
    "Valid To [GMT]": ""
},
{
    "CA Owner": "Macao Post and Telecommunications eSignTrust Certification Authority",
    "Certificate ID": "",
    "Certificate Issuer Common Name": "",
    "Certificate Issuer Organization": "",
    "Certificate Issuer Organizational Unit": "",
    "Certificate Serial Number": "",
    "Certificate Subject Common Name": "",
    "Certificate Subject Organization": "",
    "Certificate Subject Organization Unit": "",
    "PEM Info": "",
    "Public Key Algorithm": "",
    "Root Certificate Name": "eSignTrust Root Certification Authority (G03)",
    "SHA-1 Fingerprint": "",
    "SHA-256 Fingerprint": "",
    "Signature Hash Algorithm": "",
    "Subject": "",
    "Valid From [GMT]": "",
    "Valid To [GMT]": ""
},
{
    "CA Owner": "YER",
    "Certificate ID": "",
    "Certificate Issuer Common Name": "",
    "Certificate Issuer Organization": "",
    "Certificate Issuer Organizational Unit": "",
    "Certificate Serial Number": "",
    "Certificate Subject Common Name": "",
    "Certificate Subject Organization": "",
    "Certificate Subject Organization Unit": "",
    "PEM Info": "",
    "Public Key Algorithm": "",
    "Root Certificate Name": "YER CA",
    "SHA-1 Fingerprint": "",
    "SHA-256 Fingerprint": "",
    "Signature Hash Algorithm": "",
    "Subject": "",
    "Valid From [GMT]": "",
    "Valid To [GMT]": ""
}
]
```

The CCADB contains four entries that have almost no information associated with, including the lack of a PEM. These are:

- IdenTrust
- Let's Encrypt Authority X3
- Macao Post and Telecommunications eSignTrust Certification Authority
- YER

Without a valid PEM the TLS Observatory cannot provide information about these entities programmatically. As such, they may have to be entered by hand.

# Intermediate Certificates

## Symmetric Differences

> The following report says that the CCADB has an EKU with OID the 1.3.6.1.4.1.311.21.5, and that there are four certificates with the provided SHA-256 fingerprints that present with this issue. There is also one EKU, ExtKeyUsageIPSECUser, that the TLS Observatory parses out that the CCADB does not have.

```json
{
    "CCADB": {
        "1.3.6.1.4.1.311.21.5": [
            "ADDCB95B146C2E7742F16E22854FAA059D5CB87D406EC85EF7486694A03D6C84",
            "24AC889974694789DBD4E125FEE1A4BBA91532056795C05244BB66400A9D0316",
            "5587A72A6F738EDECEF67387116DE8D19370EAF3C6B272C49AF9BABA1795FD87",
            "96EF33C24A8B1F16CF170F43221E17E62AFF690A8B014F24529BFEB38F40A0DA"
        ],
    },
    "Observatory": {
    	"ExtKeyUsageIPSECUser": [
            "7B464DC384FDB1A525C2CC279ED0C7CFAD24BECF72C46A7D7093D157C217607E"
        ]
    }
}
```

The following are reports of the symmetric differences of all columns of the intermediate certificate report.

- [CRL URL(s)](intermediate/?fname=CRLURL(s))
- [Certificate ID](intermediate/?fname=CertificateID)
- [Certificate Issuer Common Name](intermediate/?fname=CertificateIssuerCommonName)
- [Certificate Issuer Organization](intermediate/?fname=CertificateIssuerOrganization)
- [Certificate Issuer Organizational Unit](intermediate/?fname=CertificateIssuerOrganizationalUnit)
- [Certificate Serial Number](intermediate/?fname=CertificateSerialNumber)
- [Certificate Subject Common Name](intermediate/?fname=CertificateSubjectCommonName)
- [Certificate Subject Organization](intermediate/?fname=CertificateSubjectOrganization)
- [Extended Key Usage](intermediate/?fname=ExtendedKeyUsage)
- [PEM Info](intermediate/?fname=PEMInfo)
- [Public Key Algorithm](intermediate/?fname=PublicKeyAlgorithm)
- [SHA-1 Fingerprint](intermediate/?fname=SHA1Fingerprint)
- [Signature Hash Algorithm](intermediate/?fname=SignatureHashAlgorithm)
- [Technically Constrained](intermediate/?fname=TechnicallyConstrained)
- [Valid From [GMT]](intermediate/?fname=ValidFromGMT)
- [Valid To [GMT]](intermediate/?fname=ValidToGMT)

## [CRL URL(s)](intermediate/?fname=CRLURL(s))
### Formatting
- The CCADB malforms this CSV field with an extra space around each `,`.

### Semantics
- The CCADB is aware of more CRL endpoints than the TLS Observatorye is parsing out. These can be found [here](intermediate/?fname=CRLURL(s)). This *appears* to be a bug in the TLS Observatory, as these URLs are present in their crt.sh results. Preliminary bug hunting has been done and we have a broad idea of why the library is truncating the list.
- The TLS Observatory contains LDAP addresses. These have been filtered out of the results as we have not expressed interest in them.

### Work to be Done
#### TLS Observatory
~~The TLS Observatory requires a fix for [issue 283](https://github.com/mozilla/tls-observatory/issues/283).~~ Fixed by vendoring Golang prerelease.
#### CCADB
- The CCADB must filter LDAP addresses on their way into the database.
- The CCADB must transform an array of URLs into a well formed CSV.

## [Certificate ID](intermediate/?fname=CertificateID)
### Formatting
- CCADB
	- Upper case
	- Colon delimited
- TLS Observatory
	- Upper case
	- No delimeters

### Semantics
- No known differences

### Work to be Done
- The CCADB should adopt the TLS Observatory's formatting choices.

## [Certificate Issuer Common Name](intermediate/?fname=CertificateIssuerCommonName)
### Formatting
- No known differences

### Semantics
- No known differences

### Work to be Done
- N/A

## [Certificate Issuer Organization](intermediate/?fname=CertificateIssuerOrganization)
### Formatting
- No known differences

### Semantics
- No known differences

### Work to be Done
- N/A

## [Certificate Issuer Organizational Unit](intermediate/?fname=CertificateIssuerOrganizationalUnit)
### Formatting
- `Certificate Issuer Organizational Unit` is a multivalued field, I.E. it should be a string CSV. However, whatever populated the CCADB seems to have used simple `join` and `split` on `","` functions in order to parse this field. [This certificate](/certificate/?sha256=C23A1F8315538A8651816E9932C044EB856C01FD99771690C863671D22C48564&certType=intermediate) is one such exampe where it appears that the CCADB `split` on `","` and then simply took only one of the answers, resulting in the drop of the rest of values.

### Semantics
- Despite the above issue, there does not appear to be any deep sematic difference.

### Work to be Done
- When the CCADB is repopulation from the TLS Observatory, it *must* address Certificate Issuer Organizational Unit as a proper array to CSV transformation. This is includes escaping values which contain control characters. A builtin CSV library should be utilized.

## [Certificate Serial Number](intermediate/?fname=CertificateSerialNumber)
### Formatting
- On average, both the CCADB *and* the TLS Observatory utitlize leading zeroes. However, the [following four certificates](/intermediate/?fname=CertificateSerialNumber) are anamolous in that the CCADB has leading zeroes, but the TLS Observatory does not.
- CCADB
	- Lower case: `01e528b46bfd2b89a9bcbcd6c7`
- TLS Observatory
	- Upper case: `01E528B46BFD2B89A9BCBCD6C7`

### Semantics
- No known differences.

### Work to be Done
- CCADB
    - The CCADB should adopt the TLS Observatory's formatting choice.
- TLS Observatory
    - Implement the fix at [issue 291](https://github.com/mozilla/tls-observatory/issues/291)

## [Certificate Subject Common Name](intermediate/?fname=CertificateSubjectCommonName)
### Formatting
- No known differences.

### Semantics
- No known differences.

### Work to be Done
- N/A

## [Certificate Subject Organization](intermediate/?fname=CertificateSubjectOrganization)
### Formatting
- No known differences.

### Semantics
- No known differences.

### Work to be Done
- N/A

## [Extended Key Usage](intermediate/?fname=ExtendedKeyUsage)

> The following is the EKU transformation code written in Golang used to generate this report. It takes the values in the CCADB and attempts to transform them into the equivalent TLS Observatory values.

```go
switch {
case eku == "1.3.6.1.5.5.7.3.9":
	translated = "ExtKeyUsageOCSPSigning"
case eku == "1.3.6.1.5.5.7.3.5":
	translated = "ExtKeyUsageIPSECEndSystem"
case eku == "1.3.6.1.5.5.7.3.6":
	translated = "ExtKeyUsageIPSECTunnel"
case eku == "1.3.6.1.5.5.7.3.7":
	translated = "ExtKeyUsageIPSECUser"
case eku == "msSGC":
	translated = "ExtKeyUsageMicrosoftServerGatedCrypto"
case eku == "nsSGC":
	translated = "ExtKeyUsageNetscapeServerGatedCrypto"
default:
	m, err := regexp.MatchString(`[0-9].*`, eku)
	if err != nil {
		// Some system error occured.
		log.Panic(err)
	}
	if m {
		// This is some arbitrary OID that we will let
		// pass through untranslated.
		translated = eku
	} else {
		// This is some non-OID EKU that we will prefix
		// with "ExtKeyUsage", because that is what the
		// Golang x509 package does for non-OID EKUs.
		//
		// E.G. `someEKU` --> `ExtKeyUsageSomeEKU`
		translated = fmt.Sprintf("ExtKeyUsage%v%v", strings.ToUpper(string(eku[0])), string(eku[1:]))
	}
}
fmted[i] = translated
}
```

### Formatting
- Some values in the CCADB are in OID form, whereas they are a string description in the TLS Observatory. The code to the right describes this mapping.

### Semantics
- The [following issues](/intermediate/?fname=ExtendedKeyUsage) have been identified. The CCADB both have several EKUs that are not present within the certificate for the TLS Observatory to parse out.
- There exist EKU entries in the CCADB that are [malformed OIDs](/certificate/?sha256=7B464DC384FDB1A525C2CC279ED0C7CFAD24BECF72C46A7D7093D157C217607E&certType=intermediate). These will be automatically corrected during the migration, but they are an interesting artifact.
- The CCADB has a handful of EKUs that the TLS Observatory are not parsing out.

	- 1.3.6.1.4.1.311.10.3.12, [MS Crypto - Signer of documents](https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography)
	- 1.3.6.1.4.1.311.10.3.4, [MS Crypto - Can use encrypted file systems](https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography)
	- 1.3.6.1.4.1.311.21.5, [MS Crypto - Enhanced Key Usage for CA encryption certificate](https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography)
	- 2.16.840.1.113733.1.8.1, [VeriSign Server Gated Crypto](http://oidref.com/2.16.840.1.113733.1.8.1)
	- 2.16.840.1.113741.1.2.3, [Intel vPro](https://knowledge.symantec.com/kb/index?page=content&id=SO18213&pmv=print&actp=PRINT)

- The TLS Observatory has a handful of EKUs that the CCADB is not aware of.

	- 1.3.6.1.5.5.7.3.14, [id-kp-eapOverLAN](http://www.oid-info.com/cgi-bin/display?oid=1.3.6.1.5.5.7.3.14&action=display)
	- 1.3.6.1.5.5.7.3.7, [IPSECUser](/certificate/?sha256=7B464DC384FDB1A525C2CC279ED0C7CFAD24BECF72C46A7D7093D157C217607E&certType=intermediate)
	- 1.3.6.1.4.1.311.21.6, these are clearly the malformed `1.3.6.1.4.1.311....` or `1.3.6.1.4.1.31...` entries
	- 1.3.6.1.4.1.311.10.3.12, these are clearly the malformed `1.3.6.1.4.1.311....` or `1.3.6.1.4.1.31...` entries

- The EKUs that the TLS Observatory are not parsing are, indeed, within the certificate. In my meetings with JC there is the notion that the EKUs are so useless that the Golang library is intentionally leaving it out. It could also possibly be the same issue that is plagueing the CRL URLs, although this hasn't been investigated yet.

### Work to be Done
- Review of the EKU mismatch.
- The CCADB must transform the received array of EKUs into a proper CSV.


## [PEM Info](intermediate/?fname=PEMInfo)

### Formatting
- Some CCADB entries have arbitrary newlines, as well as an arbitrary number of columns per line. These are technically fine, albeit inconsistent.
- The TLS Observatory returns what is not, _technically_, a PEM as it does not include the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` header/footer.

### Semantics
- No known differences.

### Work to be Done
- N/A

## [Public Key Algorithm](intermediate/?fname=PublicKeyAlgorithm)

> The TLS Observatory returns an aggregate structure formed as follows:

```json
{
	"key": {
	            "alg": "RSA",
	            "exponent": 3,      
	            "size": 2048
	}
}
```

> or...

```json
{
	"key": {
	            "alg": "ECDSA",
	            "curve": "P-384",      
	            "size": 384
	}
}
```

> This needs to be transformed to:

```json
"RSA 2048 bits"
```

> The Golang code used for this report is as follows (it assumes all EC curves are SECP):

```go
// Constructs a single string from the observatory public key object.
func MapAlgorithm(key observatory.Key) string {
	switch key.Alg {
	case "RSA":
		return fmt.Sprintf("RSA %v bits", key.Size)
	case "ECDSA":
		return fmt.Sprintf("EC secp%vr1", key.Size)
	default:
		log.Panicf("Could not understand public key algorith: %v\n", key)
		return ""
	}
}
```

### Formatting
- The TLS Observatory returns aggregate structure. This must be transformed into a single string. An example is given to the right.

### Semantics
- No known differences.

### Work to be Done
- The CCADB *must* perform a mapping of the aggregate type to a single string. Ideally, the resulting string should be uniquely traceable back to the original structure.

## [SHA-1 Fingerprint](intermediate/?fname=SHA1Fingerprint)
### Formatting
- CCADB is colon delimited.
- TLS Observatory is not colon delimited.

### Semantics
- No known differences.

### Work to be Done
- N/A

## [Signature Hash Algorithm](intermediate/?fname=SignatureHashAlgorithm)

> A mapping of the strings used in the CCADB to the string used in the TLS Observatory

```go
// converts ccadb to obs
func MapSignature(signature string) string {
	// hacky hack McHacks
	switch signature {
	case "sha1WithRSAEncryption":
		return "SHA1WithRSA"
	case "sha256WithRSAEncryption":
		return "SHA256WithRSA"
	case "sha384WithRSAEncryption":
		return "SHA384WithRSA"
	case "sha512WithRSAEncryption":
		return "SHA512WithRSA"
	case "ecdsaWithSHA256":
		return "ECDSAWithSHA256"
	case "ecdsaWithSHA384":
		return "ECDSAWithSHA384"
	case "md5WithRSAEncryption":
		return "MD5WithRSA"
	case "1.2.840.113549.1.1.2":
		return "MD2WithRSA"
	case "":
		return ""
	default:
		log.Panicf("Could not understand Signature Hash Algorithm: %v\n", signature)
		return ""
	}
}
```

### Formatting
- The CCADB and the TLS Observatory use different string enums to mean the same thing.

### Semantics
- The [following certificates](/intermediate/?fname=SignatureHashAlgorithm) are identified "Frankencerts". These certificates have been [reported as a misissuance in Bugzilla](https://bugzilla.mozilla.org/show_bug.cgi?id=1418146#c4).

### Work to be Done
- For purpose of ease, the CCADB should accept the TLS Observatory's string enums.

## [Technically Constrained](intermediate/?fname=TechnicallyConstrained)
### Formatting
- The CCADB uses "true" and "false" whereas the TLS Observatory uses "1" and "0".

### Semantics
- No known differences.

### Work to be Done
- N/A

## [Valid From [GMT]](intermediate/?fname=ValidFromGMT)
### Formatting
- The CCADB format is "2006 Jan 02".
- The TLS Observatory format is 2006-01-02T15:04:05Z"

### Semantics
- The TLS Observatory provides higher resolution on time (minutes and seconds). However, they are otherwise the same.

### Work to be Done
- N/A

## [Valid To [GMT]](intermediate/?fname=ValidToGMT)
### Formatting
- The CCADB format is "2006 Jan 02".
- The TLS Observatory format is 2006-01-02T15:04:05Z"

### Semantics
- The TLS Observatory provides higher resolution on time (minutes and seconds). However, they are otherwise the same.

### Work to be Done
- N/A

# Root Certificates

## Symmetric Differences

> The following report says that the CCADB has an EKU with OID the 1.3.6.1.4.1.311.21.5, and that there are four certificates with the provided SHA-256 fingerprints that present with this issue. There is also one EKU, ExtKeyUsageIPSECUser, that the TLS Observatory parses out that the CCADB does not have.

```json
{
    "CCADB": {
        "1.3.6.1.4.1.311.21.5": [
            "ADDCB95B146C2E7742F16E22854FAA059D5CB87D406EC85EF7486694A03D6C84",
            "24AC889974694789DBD4E125FEE1A4BBA91532056795C05244BB66400A9D0316",
            "5587A72A6F738EDECEF67387116DE8D19370EAF3C6B272C49AF9BABA1795FD87",
            "96EF33C24A8B1F16CF170F43221E17E62AFF690A8B014F24529BFEB38F40A0DA"
        ],
    },
    "Observatory": {
    	"ExtKeyUsageIPSECUser": [
            "7B464DC384FDB1A525C2CC279ED0C7CFAD24BECF72C46A7D7093D157C217607E"
        ]
    }
}
```

The following are reports of the symmetric differences of all columns of the intermediate certificate report.

- [Certificate ID](root/?fname=CertificateID)
- [Certificate Issuer Common Name](root/?fname=CertificateIssuerCommonName)
- [Certificate Issuer Organization](root/?fname=CertificateIssuerOrganization)
- [Certificate Issuer Organizational Unit](root/?fname=CertificateIssuerOrganizationalUnit)
- [Certificate Serial Number](root/?fname=CertificateSerialNumber)
- [Certificate Subject Common Name](root/?fname=CertificateSubjectCommonName)
- [Certificate Subject Organization](root/?fname=CertificateSubjectOrganization)
- [Certificate Subject Organization Unit](root/?fname=CertificateSubjectOrganizationUnit)
- [PEM Info](root/?fname=PEMInfo)
- [Public Key Algorithm](root/?fname=PublicKeyAlgorithm)
- [SHA-1 Fingerprint](root/?fname=SHA1Fingerprint)
- [Signature Hash Algorithm](root/?fname=SignatureHashAlgorithm)
- [Subject](root/?fname=Subject)
- [Valid From [GMT]](root/?fname=ValidFromGMT)
- [Valid To [GMT]](root/?fname=ValidToGMT)

## [Certificate ID](root/?fname=CertificateID)
### Formatting
- CCADB
	- Upper case
	- Colon delimited
- TLS Observatory
	- Upper case
	- No delimeters

### Semantics
- No known differences

## [Certificate Issuer Common Name](root/?fname=CertificateIssuerCommonName)
### Formatting
- No known differences

### Semantics
- There is [one certificate ](/certificate/?sha256=CD201256FE5CED0BFFF8DF595FFF36B1416D5313A999F532EF4A9915DF96DEE0&certType=root)that has conflicting names.

### Work to be Done
- N/A

## [Certificate Issuer Organization](root/?fname=CertificateIssuerOrganization)
### Formatting
- No known differences

### Semantics
- No known differences

### Work to be Done
- N/A

## [Certificate Issuer Organizational Unit](root/?fname=CertificateIssuerOrganizationalUnit)
- `Certificate Issuer Organizational Unit` is a multivalued field, I.E. it should be a string CSV. However, whatever populated the CCADB seems to have used simple `join` and `split` on `","` functions in order to parse this field. [This certificate](/certificate/?sha256=C23A1F8315538A8651816E9932C044EB856C01FD99771690C863671D22C48564&certType=intermediate) is one such exampe where it appears that the CCADB `split` on `","` and then simply took only one of the answers, resulting in the drop of the rest of values.

### Semantics
- Despite the above issue, there does not appear to be any deep sematic difference.

### Work to be Done
- When the CCADB is repopulation from the TLS Observatory, it *must* address Certificate Issuer Organizational Unit as a proper array to CSV transformation. This is includes escaping values which contain control characters. A builtin CSV library should be utilized.

## [Certificate Serial Number](root/?fname=CertificateSerialNumber)
### Formatting
- CCADB
	- Lower case: `01e528b46bfd2b89a9bcbcd6c7`
- TLS Observatory
	- Upper case: `01E528B46BFD2B89A9BCBCD6C7`

### Semantics
- No known differences.

### Work to be Done
- The CCADB should adopt the TLS Observatory's formatting choice.

## [Certificate Subject Common Name](root/?fname=CertificateSubjectCommonName)
### Formatting
- No known differences.

### Semantics
- There is [one certificate ](/certificate/?sha256=CD201256FE5CED0BFFF8DF595FFF36B1416D5313A999F532EF4A9915DF96DEE0&certType=root)that has conflicting names.

### Work to be Done
- N/A

## [Certificate Subject Organization](root/?fname=CertificateSubjectOrganization)
### Formatting
- No known differences.

### Semantics
- There is [one certificate](https://ccadb.chenderson.org/certificate/?sha256=EBC5570C29018C4D67B1AA127BAF12F703B4611EBC17B7DAB5573894179B93FA&certType=root) that has a conflicting Certificate Subject Organization.

### Work to be Done
- N/A

## [Certificate Subject Organization Unit](root/?fname=CertificateSubjectOrganizationUnit)
- `Certificate Issuer Organizational Unit` is a multivalued field, I.E. it should be a string CSV. However, whatever populated the CCADB seems to have used simple `join` and `split` on `","` functions in order to parse this field. [This certificate](/certificate/?sha256=83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B&certType=root) is one such exampe where it appears that the CCADB `split` on `","` and then simply took only one of the answers, resulting in the drop of the rest of values.

### Semantics
- Despite the above issue, there does not appear to be any deep semantic difference.

### Work to be Done
- When the CCADB is repopulation from the TLS Observatory, it *must* address Certificate Issuer Organizational Unit as a proper array to CSV transformation. This is includes escaping values which contain control characters. A builtin CSV library should be utilized.

## [PEM Info](root/?fname=PEMInfo)
- Some CCADB entries have arbitrary newlines, as well as an arbitrary number of columns per line. These are technically fine, albeit inconsistent.
- The TLS Observatory returns what is not, _technically_, a PEM as it does not include the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` header/footer.

### Semantics
- No known differences.

### Work to be Done
- N/A

## [Public Key Algorithm](root/?fname=PublicKeyAlgorithm)
> The TLS Observatory returns an aggregate structure formed as follows:

```json
{
	"key": {
	            "alg": "RSA",
	            "exponent": 3,      
	            "size": 2048
	}
}
```

> or...

```json
{
	"key": {
	            "alg": "ECDSA",
	            "curve": "P-384",      
	            "size": 384
	}
}
```

> This needs to be transformed to:

```json
"RSA 2048 bits"
```

> The Golang code used for this report is as follows (it assumes all EC curves are SECP):

```go
// Constructs a single string from the observatory public key object.
func MapAlgorithm(key observatory.Key) string {
	switch key.Alg {
	case "RSA":
		return fmt.Sprintf("RSA %v bits", key.Size)
	case "ECDSA":
		return fmt.Sprintf("EC secp%vr1", key.Size)
	default:
		log.Panicf("Could not understand public key algorith: %v\n", key)
		return ""
	}
}
```

### Formatting
- The TLS Observatory returns aggregate structure. This must be transformed into a single string. An example is given to the right.

### Semantics
- No known differences.

### Work to be Done
- The CCADB *must* perform a mapping of the aggregate type to a single string. Ideally, the resulting string should be uniquely traceable back to the original structure.

## [SHA-1 Fingerprint](root/?fname=SHA1Fingerprint)
### Formatting
- CCADB is colon delimited.
- TLS Observatory is not colon delimited.

### Semantics
- No known differences.

### Work to be Done
- N/A

## [Signature Hash Algorithm](root/?fname=SignatureHashAlgorithm)
> A mapping of the strings used in the CCADB to the string used in the TLS Observatory

```go
// converts ccadb to obs
func MapSignature(signature string) string {
	// hacky hack McHacks
	switch signature {
	case "sha1WithRSAEncryption":
		return "SHA1WithRSA"
	case "sha256WithRSAEncryption":
		return "SHA256WithRSA"
	case "sha384WithRSAEncryption":
		return "SHA384WithRSA"
	case "sha512WithRSAEncryption":
		return "SHA512WithRSA"
	case "ecdsaWithSHA256":
		return "ECDSAWithSHA256"
	case "ecdsaWithSHA384":
		return "ECDSAWithSHA384"
	case "md5WithRSAEncryption":
		return "MD5WithRSA"
	case "1.2.840.113549.1.1.2":
		return "MD2WithRSA"
	case "":
		return ""
	default:
		log.Panicf("Could not understand Signature Hash Algorithm: %v\n", signature)
		return ""
	}
}
```

### Formatting
- The CCADB and the TLS Observatory use different string enums to mean the same thing.

### Semantics
- No known differences.

### Work to be Done
- For purpose of ease, the CCADB should accept the TLS Observatory's string enums.

## [Subject](root/?fname=Subject)
### Formatting
- The CCADB does not format Distinguished Names correctly. Multivalued RDNs are dropped and RDNs with DN special characters are not properly escaped.

### Semantics
- No known differences, although it is difficult since the CCADB is missing information due to malformed DNs.

### Work to be Done
- When the CCADB generates a Distinguished Name, or Relative Distinguished Name, it must strictly adhere to [RFC 1779](https://tools.ietf.org/html/rfc1779).

## [Valid From [GMT]](root/?fname=ValidFromGMT)
### Formatting
- The CCADB format is "2006 Jan 02".
- The TLS Observatory format is 2006-01-02T15:04:05Z"

### Semantics
- The TLS Observatory provides higher resolution on time (minutes and seconds). However, they are otherwise the same.

### Work to be Done
- N/A

## [Valid To [GMT]](root/?fname=ValidToGMT)
### Formatting
- The CCADB format is "2006 Jan 02".
- The TLS Observatory format is 2006-01-02T15:04:05Z"

### Semantics
- The TLS Observatory provides higher resolution on time (minutes and seconds). However, they are otherwise the same.

### Work to be Done
- N/A
