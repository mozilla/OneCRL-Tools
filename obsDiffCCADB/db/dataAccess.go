package db

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/mozilla/OneCRL-Tools/ccadb"
	"github.com/mozilla/OneCRL-Tools/obsDiffCCADB"
	"github.com/mozilla/OneCRL-Tools/observatory"
)

// PersistCCADBRoots writes all roots certificates to the DB.
// Duplicate certificates are ignored.
func PersistCCADBRoots(roots []*ccadb.Certificate) {
	defer func() {
		// @TODO DEBUG ERASE ME
		if err := recover(); err != nil {
			log.Println(fmt.Sprintf("%v\n", err))
		}
	}()
	for _, e := range roots {
		if !checkCCADBRootDuplicates(e, e.GetOrPanic(ccadb.SHA256Fingerprint)) {
			continue
		}
		err := ExecuteTransactionalDDL(insertCCADBRootQuery,
			e.GetOrPanic(ccadb.CAOwner),
			e.GetOrPanic(ccadb.RootCertificateName),
			e.GetOrPanic(ccadb.CertificateIssuerCommonName),
			e.GetOrPanic(ccadb.CertificateIssuerOrganization),
			e.GetOrPanic(ccadb.CertificateIssuerOrganizationalUnit),
			e.GetOrPanic(ccadb.CertificateSubjectCommonName),
			e.GetOrPanic(ccadb.CertificateSubjectOrganization),
			e.GetOrPanic(ccadb.CertificateSubjectOrganizationUnit),
			e.GetOrPanic(ccadb.Subject),
			e.GetOrPanic(ccadb.ValidFromGMT),
			e.GetOrPanic(ccadb.ValidToGMT),
			e.GetOrPanic(ccadb.CertificateSerialNumber),
			e.GetOrPanic(ccadb.SignatureHashAlgorithm),
			e.GetOrPanic(ccadb.PublicKeyAlgorithm),
			e.GetOrPanic(ccadb.SHA1Fingerprint),
			e.GetOrPanic(ccadb.SHA256Fingerprint),
			e.GetOrPanic(ccadb.CertificateID),
			e.GetOrPanic(ccadb.PEMInfo))
		if err != nil {
			log.Panic(err)
		}
		normalizedRoot := obsDiffCCADB.NormalizeRoot(*e)
		err = ExecuteTransactionalDDL(insertCCADBRootNormalizedQuery,
			normalizedRoot.GetOrPanic(ccadb.CAOwner),
			normalizedRoot.GetOrPanic(ccadb.RootCertificateName),
			normalizedRoot.GetOrPanic(ccadb.CertificateIssuerCommonName),
			normalizedRoot.GetOrPanic(ccadb.CertificateIssuerOrganization),
			normalizedRoot.GetOrPanic(ccadb.CertificateIssuerOrganizationalUnit),
			normalizedRoot.GetOrPanic(ccadb.CertificateSubjectCommonName),
			normalizedRoot.GetOrPanic(ccadb.CertificateSubjectOrganization),
			normalizedRoot.GetOrPanic(ccadb.CertificateSubjectOrganizationUnit),
			normalizedRoot.GetOrPanic(ccadb.Subject),
			normalizedRoot.GetOrPanic(ccadb.ValidFromGMT),
			normalizedRoot.GetOrPanic(ccadb.ValidToGMT),
			normalizedRoot.GetOrPanic(ccadb.CertificateSerialNumber),
			normalizedRoot.GetOrPanic(ccadb.SignatureHashAlgorithm),
			normalizedRoot.GetOrPanic(ccadb.PublicKeyAlgorithm),
			normalizedRoot.GetOrPanic(ccadb.SHA1Fingerprint),
			normalizedRoot.GetOrPanic(ccadb.SHA256Fingerprint),
			normalizedRoot.GetOrPanic(ccadb.CertificateID),
			normalizedRoot.GetOrPanic(ccadb.PEMInfo))
		if err != nil {
			log.Panic(err)
		}
	}
}

// PersistCCADBIntermediates writes all intermediate certificates to the DB.
// Duplicate certificates are ignored.
func PersistCCADBIntermediates(intermediates []*ccadb.Certificate) {
	for _, e := range intermediates {
		if !checkCCADBIntermediateDuplicates(e, e.GetOrPanic(ccadb.SHA256Fingerprint)) {
			continue
		}
		err := ExecuteTransactionalDDL(insertCCADBIntermediateQuery,
			e.GetOrPanic(ccadb.PEMInfo),
			e.GetOrPanic(ccadb.SHA1Fingerprint),
			e.GetOrPanic(ccadb.SHA256Fingerprint),
			e.GetOrPanic(ccadb.CertificateID),
			e.GetOrPanic(ccadb.CertificateIssuerCommonName),
			e.GetOrPanic(ccadb.CertificateIssuerOrganization),
			e.GetOrPanic(ccadb.CertificateIssuerOrganizationalUnit),
			e.GetOrPanic(ccadb.PublicKeyAlgorithm),
			e.GetOrPanic(ccadb.CertificateSerialNumber),
			e.GetOrPanic(ccadb.SignatureHashAlgorithm),
			e.GetOrPanic(ccadb.CertificateSubjectCommonName),
			e.GetOrPanic(ccadb.CertificateSubjectOrganization),
			e.GetOrPanic(ccadb.ValidFromGMT),
			e.GetOrPanic(ccadb.ValidToGMT),
			e.GetOrPanic(ccadb.CRLURLs),
			e.GetOrPanic(ccadb.ExtendedKeyUsage),
			e.GetOrPanic(ccadb.TechnicallyConstrained))
		if err != nil {
			log.Panic(err)
		}
		normalizedIntermediate := obsDiffCCADB.NormalizeIntermediate(*e)
		err = ExecuteTransactionalDDL(insertCCADBIntermediateNormalizedQuery,
			normalizedIntermediate.GetOrPanic(ccadb.PEMInfo),
			normalizedIntermediate.GetOrPanic(ccadb.SHA1Fingerprint),
			normalizedIntermediate.GetOrPanic(ccadb.SHA256Fingerprint),
			normalizedIntermediate.GetOrPanic(ccadb.CertificateID),
			normalizedIntermediate.GetOrPanic(ccadb.CertificateIssuerCommonName),
			normalizedIntermediate.GetOrPanic(ccadb.CertificateIssuerOrganization),
			normalizedIntermediate.GetOrPanic(ccadb.CertificateIssuerOrganizationalUnit),
			normalizedIntermediate.GetOrPanic(ccadb.PublicKeyAlgorithm),
			normalizedIntermediate.GetOrPanic(ccadb.CertificateSerialNumber),
			normalizedIntermediate.GetOrPanic(ccadb.SignatureHashAlgorithm),
			normalizedIntermediate.GetOrPanic(ccadb.CertificateSubjectCommonName),
			normalizedIntermediate.GetOrPanic(ccadb.CertificateSubjectOrganization),
			normalizedIntermediate.GetOrPanic(ccadb.ValidFromGMT),
			normalizedIntermediate.GetOrPanic(ccadb.ValidToGMT),
			normalizedIntermediate.GetOrPanic(ccadb.CRLURLs),
			normalizedIntermediate.GetOrPanic(ccadb.ExtendedKeyUsage),
			normalizedIntermediate.GetOrPanic(ccadb.TechnicallyConstrained))
		if err != nil {
			log.Panic(err)
		}
	}
}

// PersistObservatoryIntermediates writes all intermediate certificates to the DB.
// Duplicate certificates are ignored.
func PersistObservatoryIntermediates(intermediates []*observatory.Certificate) {
	seen := make(map[string]bool)
	for _, e := range intermediates {
		if _, ok := seen[e.Hashes.SHA256]; ok {
			continue
		}
		seen[e.Hashes.SHA256] = true
		sort.Strings(e.X509v3Extensions.ExtendedKeyUsage)
		crlUrls := make([]string, 0)
		for _, url := range e.X509v3Extensions.CRLDistributionPoint {
			if !strings.HasPrefix(url, "ldap") {
				crlUrls = append(crlUrls, strings.TrimSpace(url))
			}
		}
		sort.Strings(crlUrls)
		err := ExecuteTransactionalDDL(insertObservatoryIntermediateQuery,
			e.Raw,
			e.Hashes.SHA1,
			e.Hashes.SHA256,
			e.Hashes.SHA256SubjectSPKI,
			e.Issuer.CN,
			obsDiffCCADB.SliceToCSV(e.Issuer.O),
			obsDiffCCADB.SliceToCSV(e.Issuer.OU),
			obsDiffCCADB.MapAlgorithm(e.Key),
			e.SerialNumber,
			e.SignatureAlgorithm,
			e.Subject.CN,
			obsDiffCCADB.SliceToCSV(e.Subject.O),
			obsDiffCCADB.MapTime(e.Validity.NotBefore),
			obsDiffCCADB.MapTime(e.Validity.NotAfter),
			obsDiffCCADB.MapCRLs(crlUrls),
			obsDiffCCADB.SliceToCSV(e.X509v3Extensions.ExtendedKeyUsage),
			e.X509v3Extensions.IsTechnicallyConstrained)
		if err != nil {
			log.Panic(err)
		}
	}
}

// PersistObservatoryRoots writes all root certificates to the DB.
// Duplicate certificates are ignored.
func PersistObservatoryRoots(roots []*observatory.Certificate) {
	seen := make(map[string]bool)
	for _, e := range roots {
		if _, ok := seen[e.Hashes.SHA256]; ok {
			continue
		}
		seen[e.Hashes.SHA256] = true
		err := ExecuteTransactionalDDL(insertObservatoryRootQuery,
			obsDiffCCADB.SliceToCSV(e.Issuer.O),
			e.Issuer.CN,
			e.Issuer.CN,
			obsDiffCCADB.SliceToCSV(e.Issuer.O),
			obsDiffCCADB.SliceToCSV(e.Issuer.OU),
			e.Subject.CN,
			obsDiffCCADB.SliceToCSV(e.Subject.O),
			obsDiffCCADB.SliceToCSV(e.Subject.OU),
			obsDiffCCADB.FmtDN(e.Subject),
			obsDiffCCADB.MapTime(e.Validity.NotBefore),
			obsDiffCCADB.MapTime(e.Validity.NotAfter),
			e.SerialNumber,
			e.SignatureAlgorithm,
			obsDiffCCADB.MapAlgorithm(e.Key),
			e.Hashes.SHA1,
			e.Hashes.SHA256,
			e.Hashes.SHA256SubjectSPKI,
			e.Raw)
		if err != nil {
			log.Panicln(err)
		}
	}
}

// checkCCADBIntermediateDuplicates ensures that any duplicate entry found within
// the CCADB is at least deeply equivalent before deduplication occurs.
// The function does not panic, but logs any discrepencies.
func checkCCADBIntermediateDuplicates(e *ccadb.Certificate, pem string) bool {
	ok := true
	query := "select * from ccadbIntermediate where `SHA-256 Fingerprint` = ?"
	for _, r := range ExecuteQueryOrPanicIntermediate(query, pem) {
		ok = false
		badFields := make(map[string]string, 0)
		// This is painful since the lefthand side is essentially a dynamically
		// declared type loaded from a CCADB query and the righthand side is
		// a proper Go type.
		if e.GetOrPanic(ccadb.PEMInfo) != r.PEMInfo {
			badFields[ccadb.PEMInfo] = r.PEMInfo
		}
		if e.GetOrPanic(ccadb.SHA1Fingerprint) != r.SHA1Fingerprint {
			badFields[ccadb.SHA1Fingerprint] = r.SHA1Fingerprint
		}
		if e.GetOrPanic(ccadb.SHA256Fingerprint) != r.SHA256Fingerprint {
			badFields[ccadb.SHA256Fingerprint] = r.SHA256Fingerprint
		}
		if e.GetOrPanic(ccadb.CertificateID) != r.CertificateID {
			badFields[ccadb.CertificateID] = r.CertificateID
		}
		if e.GetOrPanic(ccadb.CertificateIssuerCommonName) != r.CertificateIssuerCommonName {
			badFields[ccadb.CertificateIssuerCommonName] = r.CertificateIssuerCommonName
		}
		if e.GetOrPanic(ccadb.CertificateIssuerOrganization) != r.CertificateIssuerOrganization {
			badFields[ccadb.CertificateIssuerOrganization] = r.CertificateIssuerOrganization
		}
		if e.GetOrPanic(ccadb.CertificateIssuerOrganizationalUnit) != r.CertificateIssuerOrganizationalUnit {
			badFields[ccadb.CertificateIssuerOrganizationalUnit] = r.CertificateIssuerOrganizationalUnit
		}
		if e.GetOrPanic(ccadb.PublicKeyAlgorithm) != r.PublicKeyAlgorithm {
			badFields[ccadb.PublicKeyAlgorithm] = r.PublicKeyAlgorithm
		}
		if e.GetOrPanic(ccadb.CertificateSerialNumber) != r.CertificateSerialNumber {
			badFields[ccadb.CertificateSerialNumber] = r.CertificateSerialNumber
		}
		if e.GetOrPanic(ccadb.SignatureHashAlgorithm) != r.SignatureHashAlgorithm {
			badFields[ccadb.SignatureHashAlgorithm] = r.SignatureHashAlgorithm
		}
		if e.GetOrPanic(ccadb.CertificateSubjectCommonName) != r.CertificateSubjectCommonName {
			badFields[ccadb.CertificateSubjectCommonName] = r.CertificateSubjectCommonName
		}
		if e.GetOrPanic(ccadb.CertificateSubjectOrganization) != r.CertificateSubjectOrganization {
			badFields[ccadb.CertificateSubjectOrganization] = r.CertificateSubjectOrganization
		}
		if e.GetOrPanic(ccadb.ValidFromGMT) != r.ValidFromGMT {
			badFields[ccadb.ValidFromGMT] = r.ValidFromGMT
		}
		if e.GetOrPanic(ccadb.ValidToGMT) != r.ValidToGMT {
			badFields[ccadb.ValidToGMT] = r.ValidToGMT
		}
		if e.GetOrPanic(ccadb.CRLURLs) != r.CRLURLs {
			badFields[ccadb.CRLURLs] = r.CRLURLs
		}
		if e.GetOrPanic(ccadb.ExtendedKeyUsage) != r.ExtendedKeyUsage {
			badFields[ccadb.ExtendedKeyUsage] = r.ExtendedKeyUsage
		}
		if e.GetOrPanic(ccadb.TechnicallyConstrained) != r.TechnicallyConstrained {
			badFields[ccadb.TechnicallyConstrained] = r.TechnicallyConstrained
		}
		for k, v := range badFields {
			log.Printf("Duplicate entry did not have equivalent values for %v.\n got %v wanted %v\n", k, v, e.GetOrPanic(k))
		}
	}
	return ok
}

// checkCCADBRootDuplicates ensures that any duplicate entry found within
// the CCADB is at least deeply equivalent before deduplication occurs.
// The function does not panic, but logs any discrepencies.
func checkCCADBRootDuplicates(e *ccadb.Certificate, pem string) bool {
	ok := true
	query := "select * from ccadbRoot where `SHA-256 Fingerprint` = ?"
	for _, r := range ExecuteQueryOrPanicRoot(query, pem) {
		ok = false
		badFields := make(map[string]string, 0)
		// This is painful since the lefthand side is essentially a dynamically
		// declared type loaded from a CCADB query and the righthand side is
		// a proper Go type.
		if e.GetOrPanic(ccadb.CAOwner) != r.CAOwner {
			badFields[ccadb.CAOwner] = r.CAOwner
		}
		if e.GetOrPanic(ccadb.RootCertificateName) != r.RootCertificateName {
			badFields[ccadb.RootCertificateName] = r.RootCertificateName
		}
		if e.GetOrPanic(ccadb.CertificateIssuerCommonName) != r.CertificateIssuerCommonName {
			badFields[ccadb.CertificateIssuerCommonName] = r.CertificateIssuerCommonName
		}
		if e.GetOrPanic(ccadb.CertificateIssuerOrganization) != r.CertificateIssuerOrganization {
			badFields[ccadb.CertificateIssuerOrganization] = r.CertificateIssuerOrganization
		}
		if e.GetOrPanic(ccadb.CertificateIssuerOrganizationalUnit) != r.CertificateIssuerOrganizationalUnit {
			badFields[ccadb.CertificateIssuerOrganizationalUnit] = r.CertificateIssuerOrganizationalUnit
		}
		if e.GetOrPanic(ccadb.CertificateSubjectCommonName) != r.CertificateSubjectCommonName {
			badFields[ccadb.CertificateSubjectCommonName] = r.CertificateSubjectCommonName
		}
		if e.GetOrPanic(ccadb.CertificateSubjectOrganization) != r.CertificateSubjectOrganization {
			badFields[ccadb.CertificateSubjectOrganization] = r.CertificateSubjectOrganization
		}
		if e.GetOrPanic(ccadb.CertificateSubjectOrganizationUnit) != r.CertificateSubjectOrganizationUnit {
			badFields[ccadb.CertificateSubjectOrganizationUnit] = r.CertificateSubjectOrganizationUnit
		}
		if e.GetOrPanic(ccadb.Subject) != r.Subject {
			badFields[ccadb.Subject] = r.Subject
		}
		if e.GetOrPanic(ccadb.ValidFromGMT) != r.ValidFromGMT {
			badFields[ccadb.ValidFromGMT] = r.ValidFromGMT
		}
		if e.GetOrPanic(ccadb.ValidToGMT) != r.ValidToGMT {
			badFields[ccadb.ValidToGMT] = r.ValidToGMT
		}
		if e.GetOrPanic(ccadb.CertificateSerialNumber) != r.CertificateSerialNumber {
			badFields[ccadb.CertificateSerialNumber] = r.CertificateSerialNumber
		}
		if e.GetOrPanic(ccadb.SignatureHashAlgorithm) != r.SignatureHashAlgorithm {
			badFields[ccadb.SignatureHashAlgorithm] = r.SignatureHashAlgorithm
		}
		if e.GetOrPanic(ccadb.PublicKeyAlgorithm) != r.PublicKeyAlgorithm {
			badFields[ccadb.PublicKeyAlgorithm] = r.PublicKeyAlgorithm
		}
		if e.GetOrPanic(ccadb.SHA1Fingerprint) != r.SHA1Fingerprint {
			badFields[ccadb.SHA1Fingerprint] = r.SHA1Fingerprint
		}
		if e.GetOrPanic(ccadb.SHA256Fingerprint) != r.SHA256Fingerprint {
			badFields[ccadb.SHA256Fingerprint] = r.SHA256Fingerprint
		}
		if e.GetOrPanic(ccadb.CertificateID) != r.CertificateID {
			badFields[ccadb.CertificateID] = r.CertificateID
		}
		if e.GetOrPanic(ccadb.PEMInfo) != r.PEMInfo {
			badFields[ccadb.PEMInfo] = r.PEMInfo
		}
		for k, v := range badFields {
			log.Printf("Duplicate entry did not have equivalent values for %v.\n got %v wanted %v\n", k, v, e.GetOrPanic(k))
		}
	}
	return ok
}

// Diff is the fingerprint of the certificate
// and the differing values that the CCADB and
// TLS Obsevatory have.
type Diff struct {
	Fingerprint string
	CCADB       string
	Observatory string
}

// Diffs is used by the buildDiffReport command.
// Query should be a join and selection on the
// desired difference.
func Diffs(query, column string) []Diff {
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	diffs := make([]Diff, 0)
	for rows.Next() {
		d := Diff{}
		err := rows.Scan(&d.Fingerprint, &d.CCADB, &d.Observatory)
		if err != nil {
			log.Fatal(err)
		}
		diffs = append(diffs, d)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	return diffs
}
