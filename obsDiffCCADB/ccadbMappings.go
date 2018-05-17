package obsDiffCCADB

// This file contains functions and definitions for normalizing a CCADB
// entry into a format that is inline with the TLS Observatory.

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/mozilla/OneCRL-Tools/ccadb"
	"github.com/mozilla/OneCRL-Tools/observatory"
)

const (
	// EmptyArray is the CCADB's chosen representation of an empty collection.
	EmptyArray = "(not present)"
)

// We use this to remove all formatting from a PEM so that we
// can later normalize them.
var pemStripper = regexp.MustCompile(`('|'|\n|-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+)`)

// NormalizeRoot transforms the given CCADB root certificate into
// the same formatting and style used by the TLS Observatory.
func NormalizeRoot(root ccadb.Certificate) *ccadb.Certificate {
	root.Set(ccadb.SignatureHashAlgorithm, MapSignature(root.GetOrPanic(ccadb.SignatureHashAlgorithm)))
	root.Set(ccadb.SHA1Fingerprint, StripColons(root.GetOrPanic(ccadb.SHA1Fingerprint)))
	root.Set(ccadb.SHA256Fingerprint, StripColons(root.GetOrPanic(ccadb.SHA256Fingerprint)))
	root.Set(ccadb.CertificateID, strings.ToUpper(StripColons(root.GetOrPanic(ccadb.CertificateID))))
	root.Set(ccadb.PEMInfo, StripPEM(root.GetOrPanic(ccadb.PEMInfo)))
	root.Set(ccadb.CertificateSerialNumber, strings.ToUpper(root.GetOrPanic(ccadb.CertificateSerialNumber)))

	root.Set(ccadb.CertificateIssuerOrganization, SliceToCSV([]string{root.GetOrPanic(ccadb.CertificateIssuerOrganization)}))
	root.Set(ccadb.CertificateIssuerOrganizationalUnit, SliceToCSV([]string{root.GetOrPanic(ccadb.CertificateIssuerOrganizationalUnit)}))
	root.Set(ccadb.CertificateSubjectOrganization, SliceToCSV([]string{root.GetOrPanic(ccadb.CertificateSubjectOrganization)}))
	root.Set(ccadb.CertificateSubjectOrganizationUnit, SliceToCSV([]string{root.GetOrPanic(ccadb.CertificateSubjectOrganizationUnit)}))
	return &root
}

// NormalizeIntermediate transforms the given CCADB intermediate certificate into
// the same formatting and style used by the TLS Observatory.
func NormalizeIntermediate(intermediate ccadb.Certificate) *ccadb.Certificate {
	intermediate.Set(ccadb.SignatureHashAlgorithm, MapSignature(intermediate.GetOrPanic(ccadb.SignatureHashAlgorithm)))
	intermediate.Set(ccadb.SHA1Fingerprint, StripColons(intermediate.GetOrPanic(ccadb.SHA1Fingerprint)))
	intermediate.Set(ccadb.SHA256Fingerprint, StripColons(intermediate.GetOrPanic(ccadb.SHA256Fingerprint)))
	intermediate.Set(ccadb.CertificateID, strings.ToUpper(StripColons(intermediate.GetOrPanic(ccadb.CertificateID))))
	intermediate.Set(ccadb.PEMInfo, StripPEM(intermediate.GetOrPanic(ccadb.PEMInfo)))
	intermediate.Set(ccadb.CertificateSerialNumber, strings.ToUpper(intermediate.GetOrPanic(ccadb.CertificateSerialNumber)))

	intermediate.Set(ccadb.CertificateIssuerOrganization, SliceToCSV([]string{intermediate.GetOrPanic(ccadb.CertificateIssuerOrganization)}))
	intermediate.Set(ccadb.CertificateIssuerOrganizationalUnit, SliceToCSV([]string{intermediate.GetOrPanic(ccadb.CertificateIssuerOrganizationalUnit)}))
	intermediate.Set(ccadb.CertificateSubjectOrganization, SliceToCSV([]string{intermediate.GetOrPanic(ccadb.CertificateSubjectOrganization)}))

	intermediate.Set(ccadb.ExtendedKeyUsage, MapExtendedKeyUsage(intermediate.GetOrPanic(ccadb.ExtendedKeyUsage)))
	intermediate.Set(ccadb.TechnicallyConstrained, MapTechnicallyConstrained(intermediate.GetOrPanic(ccadb.TechnicallyConstrained)))
	intermediate.Set(ccadb.CRLURLs, MapArray(intermediate.GetOrPanic(ccadb.CRLURLs)))
	return &intermediate
}

// StripPEM removes all formatting from the given
// PEM string.
func StripPEM(p string) string {
	return pemStripper.ReplaceAllString(p, "")
}

// MapSignature maps the string describing the certificate's
// signature hash and encryption algorithm from the CCADB's
// enum set to the TLS Observatory's enum set.
func MapSignature(signature string) string {
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

// MapTechnicallyConstrained maps the strings "false"
// and "true" to the strings "0" and "1", respectively.
func MapTechnicallyConstrained(t string) string {
	if t == "false" {
		return "0"
	}
	return "1"
}

// StripColons removes all colons. Typically from fingerprints.
func StripColons(s string) string {
	return strings.Replace(s, ":", "", -1)
}

// MapExtendedKeyUsage transforms the CCADB EKU format
// and naming to the TLS Observatory's format and naming.
func MapExtendedKeyUsage(extendedKeyUsage string) string {
	if extendedKeyUsage == EmptyArray {
		return ""
	}
	ekus := CSVToSlice(extendedKeyUsage)
	if len(ekus) == 0 {
		return ""
	}
	fmted := make([]string, len(ekus))
	for i, eku := range ekus {
		eku = strings.TrimSpace(eku)
		var translated string
		// These handful have direct translations from the CCADB to
		// the Observatory. The default case handles EKUs which either the
		// Observatory doesn't have a name for or those which are named
		// and need to be put into the Observatory's format.
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
			// Does it start with numbers? Then it's some OID.
			m, err := regexp.MatchString(`[0-9].*`, eku)
			if err != nil {
				log.Panic(err)
			}
			if m {
				// If it's some OID, then take it literally.
				translated = eku
			} else {
				// Otherwise, do what the Observatory does and camel case it
				// and prepend it with ExtKeyUsage.
				translated = fmt.Sprintf("ExtKeyUsage%v%v", strings.ToUpper(string(eku[0])), string(eku[1:]))
			}
		}
		fmted[i] = translated
	}
	return SliceToCSV(fmted)
}

// MapAlgorithm maps the public key algorithm name from the CCADB
// format to the TLS Observatory's format.
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

// MapArray transforms the string representation of a CCADB
// array to the string representation of a TLS Observatory array.
func MapArray(a string) string {
	if a == EmptyArray || a == "" {
		return ""
	}
	s := CSVToSlice(a)
	return SliceToCSV(s)
}
