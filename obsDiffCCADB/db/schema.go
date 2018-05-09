package db

import (
	"database/sql"
	"log"
	"os"
	"path"
	"sync"

	// sqlite3 package merely needs the import side-effect.
	_ "github.com/mattn/go-sqlite3"
)

// DBName is the name of the target database file.
const DBName = "ccadb_migration.sql"
const driver = "sqlite3"

var dropTables = []string{`DROP TABLE IF EXISTS 'ccadbIntermediate'`,
	`DROP TABLE IF EXISTS 'ccadbIntermediateNormalized'`,
	`DROP TABLE IF EXISTS 'ccadbRoot'`,
	`DROP TABLE IF EXISTS 'ccadbRootNormalized'`,
	`DROP TABLE IF EXISTS 'observatoryIntermediate'`,
	`DROP TABLE IF EXISTS 'observatoryRoot'`}

var createTables = []string{`
	CREATE TABLE IF NOT EXISTS 'ccadbIntermediate' (
    'PEM Info' TEXT,
	'SHA-1 Fingerprint' TEXT,
	'SHA-256 Fingerprint' TEXT PRIMARY KEY,
	'Certificate ID' TEXT,
	'Certificate Issuer Common Name' TEXT,
	'Certificate Issuer Organization' TEXT,
	'Certificate Issuer Organizational Unit' TEXT,
	'Public Key Algorithm' TEXT,
	'Certificate Serial Number' TEXT,
	'Signature Hash Algorithm' TEXT,
	'Certificate Subject Common Name' TEXT,
	'Certificate Subject Organization' TEXT,
	'Valid From [GMT]' TEXT,
	'Valid To [GMT]' TEXT,
	'CRL URL(s)' TEXT,
	'Extended Key Usage' TEXT,
	'Technically Constrained' TEXT
);`, `
	CREATE TABLE IF NOT EXISTS 'ccadbIntermediateNormalized' (
    'PEM Info' TEXT,
	'SHA-1 Fingerprint' TEXT,
	'SHA-256 Fingerprint' TEXT PRIMARY KEY,
	'Certificate ID' TEXT,
	'Certificate Issuer Common Name' TEXT,
	'Certificate Issuer Organization' TEXT,
	'Certificate Issuer Organizational Unit' TEXT,
	'Public Key Algorithm' TEXT,
	'Certificate Serial Number' TEXT,
	'Signature Hash Algorithm' TEXT,
	'Certificate Subject Common Name' TEXT,
	'Certificate Subject Organization' TEXT,
	'Valid From [GMT]' TEXT,
	'Valid To [GMT]' TEXT,
	'CRL URL(s)' TEXT,
	'Extended Key Usage' TEXT,
	'Technically Constrained' TEXT
);`, `
CREATE TABLE IF NOT EXISTS 'ccadbRoot' (
	'CA Owner' TEXT,
	'Root Certificate Name' TEXT,
	'Certificate Issuer Common Name' TEXT,
	'Certificate Issuer Organization' TEXT,
	'Certificate Issuer Organizational Unit' TEXT,
	'Certificate Subject Common Name' TEXT,
	'Certificate Subject Organization' TEXT,
	'Certificate Subject Organization Unit' TEXT,
	'Subject' TEXT,
	'Valid From [GMT]' TEXT,
	'Valid To [GMT]' TEXT,
	'Certificate Serial Number' TEXT,
	'Signature Hash Algorithm' TEXT,
	'Public Key Algorithm' TEXT,
	'SHA-1 Fingerprint' TEXT,
	'SHA-256 Fingerprint' TEXT PRIMARY KEY,
	'Certificate ID' TEXT,
	'PEM Info' TEXT
);`, `
CREATE TABLE IF NOT EXISTS 'ccadbRootNormalized' (
	'CA Owner' TEXT,
	'Root Certificate Name' TEXT,
	'Certificate Issuer Common Name' TEXT,
	'Certificate Issuer Organization' TEXT,
	'Certificate Issuer Organizational Unit' TEXT,
	'Certificate Subject Common Name' TEXT,
	'Certificate Subject Organization' TEXT,
	'Certificate Subject Organization Unit' TEXT,
	'Subject' TEXT,
	'Valid From [GMT]' TEXT,
	'Valid To [GMT]' TEXT,
	'Certificate Serial Number' TEXT,
	'Signature Hash Algorithm' TEXT,
	'Public Key Algorithm' TEXT,
	'SHA-1 Fingerprint' TEXT,
	'SHA-256 Fingerprint' TEXT PRIMARY KEY,
	'Certificate ID' TEXT,
	'PEM Info' TEXT
);`, `
CREATE TABLE IF NOT EXISTS 'observatoryIntermediate' (
    'PEM Info' TEXT,
	'SHA-1 Fingerprint' TEXT,
	'SHA-256 Fingerprint' TEXT PRIMARY KEY,
	'Certificate ID' TEXT,
	'Certificate Issuer Common Name' TEXT,
	'Certificate Issuer Organization' TEXT,
	'Certificate Issuer Organizational Unit' TEXT,
	'Public Key Algorithm' TEXT,
	'Certificate Serial Number' TEXT,
	'Signature Hash Algorithm' TEXT,
	'Certificate Subject Common Name' TEXT,
	'Certificate Subject Organization' TEXT,
	'Valid From [GMT]' TEXT,
	'Valid To [GMT]' TEXT,
	'CRL URL(s)' TEXT,
	'Extended Key Usage' TEXT,
	'Technically Constrained' TEXT
);`, `
CREATE TABLE IF NOT EXISTS 'observatoryRoot' (
	'CA Owner' TEXT,
	'Root Certificate Name' TEXT,
	'Certificate Issuer Common Name' TEXT,
	'Certificate Issuer Organization' TEXT,
	'Certificate Issuer Organizational Unit' TEXT,
	'Certificate Subject Common Name' TEXT,
	'Certificate Subject Organization' TEXT,
	'Certificate Subject Organization Unit' TEXT,
	'Subject' TEXT,
	'Valid From [GMT]' TEXT,
	'Valid To [GMT]' TEXT,
	'Certificate Serial Number' TEXT,
	'Signature Hash Algorithm' TEXT,
	'Public Key Algorithm' TEXT,
	'SHA-1 Fingerprint' TEXT,
	'SHA-256 Fingerprint' TEXT PRIMARY KEY,
	'Certificate ID' TEXT,
	'PEM Info' TEXT
);`}

const insertCCADBIntermediateQuery = `
INSERT INTO ccadbIntermediate (
   	'PEM Info',
	'SHA-1 Fingerprint',
	'SHA-256 Fingerprint',
	'Certificate ID',
	'Certificate Issuer Common Name',
	'Certificate Issuer Organization',
	'Certificate Issuer Organizational Unit',
	'Public Key Algorithm',
	'Certificate Serial Number',
	'Signature Hash Algorithm',
	'Certificate Subject Common Name',
	'Certificate Subject Organization',
	'Valid From [GMT]',
	'Valid To [GMT]',
	'CRL URL(s)',
	'Extended Key Usage',
	'Technically Constrained'
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const insertCCADBIntermediateNormalizedQuery = `
INSERT INTO ccadbIntermediateNormalized (
   	'PEM Info',
	'SHA-1 Fingerprint',
	'SHA-256 Fingerprint',
	'Certificate ID',
	'Certificate Issuer Common Name',
	'Certificate Issuer Organization',
	'Certificate Issuer Organizational Unit',
	'Public Key Algorithm',
	'Certificate Serial Number',
	'Signature Hash Algorithm',
	'Certificate Subject Common Name',
	'Certificate Subject Organization',
	'Valid From [GMT]',
	'Valid To [GMT]',
	'CRL URL(s)',
	'Extended Key Usage',
	'Technically Constrained'
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const insertCCADBRootQuery = `
INSERT INTO ccadbRoot (
	'CA Owner',
	'Root Certificate Name',
	'Certificate Issuer Common Name',
	'Certificate Issuer Organization',
	'Certificate Issuer Organizational Unit',
	'Certificate Subject Common Name',
	'Certificate Subject Organization',
	'Certificate Subject Organization Unit',
	'Subject',
	'Valid From [GMT]',
	'Valid To [GMT]',
	'Certificate Serial Number',
	'Signature Hash Algorithm',
	'Public Key Algorithm',
	'SHA-1 Fingerprint',
	'SHA-256 Fingerprint',
	'Certificate ID',
	'PEM Info'
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const insertCCADBRootNormalizedQuery = `
INSERT INTO ccadbRootNormalized (
	'CA Owner',
	'Root Certificate Name',
	'Certificate Issuer Common Name',
	'Certificate Issuer Organization',
	'Certificate Issuer Organizational Unit',
	'Certificate Subject Common Name',
	'Certificate Subject Organization',
	'Certificate Subject Organization Unit',
	'Subject',
	'Valid From [GMT]',
	'Valid To [GMT]',
	'Certificate Serial Number',
	'Signature Hash Algorithm',
	'Public Key Algorithm',
	'SHA-1 Fingerprint',
	'SHA-256 Fingerprint',
	'Certificate ID',
	'PEM Info'
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const insertObservatoryIntermediateQuery = `
INSERT INTO observatoryIntermediate (
   	'PEM Info',
	'SHA-1 Fingerprint',
	'SHA-256 Fingerprint',
	'Certificate ID',
	'Certificate Issuer Common Name',
	'Certificate Issuer Organization',
	'Certificate Issuer Organizational Unit',
	'Public Key Algorithm',
	'Certificate Serial Number',
	'Signature Hash Algorithm',
	'Certificate Subject Common Name',
	'Certificate Subject Organization',
	'Valid From [GMT]',
	'Valid To [GMT]',
	'CRL URL(s)',
	'Extended Key Usage',
	'Technically Constrained'
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const insertObservatoryRootQuery = `
INSERT INTO observatoryRoot (
	'CA Owner',
	'Root Certificate Name',
	'Certificate Issuer Common Name',
	'Certificate Issuer Organization',
	'Certificate Issuer Organizational Unit',
	'Certificate Subject Common Name',
	'Certificate Subject Organization',
	'Certificate Subject Organization Unit',
	'Subject',
	'Valid From [GMT]',
	'Valid To [GMT]',
	'Certificate Serial Number',
	'Signature Hash Algorithm',
	'Public Key Algorithm',
	'SHA-1 Fingerprint',
	'SHA-256 Fingerprint',
	'Certificate ID',
	'PEM Info'
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

var db *sql.DB
var lock sync.Mutex

// Intermediate represents a normalized intermediate certificate.
type Intermediate struct {
	PEMInfo                             string
	SHA1Fingerprint                     string
	SHA256Fingerprint                   string
	CertificateID                       string
	CertificateIssuerCommonName         string
	CertificateIssuerOrganization       string
	CertificateIssuerOrganizationalUnit string
	PublicKeyAlgorithm                  string
	CertificateSerialNumber             string
	SignatureHashAlgorithm              string
	CertificateSubjectCommonName        string
	CertificateSubjectOrganization      string
	ValidFromGMT                        string
	ValidToGMT                          string
	CRLURLs                             string
	ExtendedKeyUsage                    string
	TechnicallyConstrained              string
}

// Root represents and normalized root certificate.
type Root struct {
	CAOwner                             string
	RootCertificateName                 string
	CertificateIssuerCommonName         string
	CertificateIssuerOrganization       string
	CertificateIssuerOrganizationalUnit string
	CertificateSubjectCommonName        string
	CertificateSubjectOrganization      string
	CertificateSubjectOrganizationUnit  string
	Subject                             string
	ValidFromGMT                        string
	ValidToGMT                          string
	CertificateSerialNumber             string
	SignatureHashAlgorithm              string
	PublicKeyAlgorithm                  string
	SHA1Fingerprint                     string
	SHA256Fingerprint                   string
	CertificateID                       string
	PEMInfo                             string
}

// ShouldWipe is a type alias for indicating if
// the database should be reset upon initialization.
type ShouldWipe bool

// Wipe will cause a deletion of the database upon initialization.
const Wipe ShouldWipe = true

// DontWipe will leave the database as is upon initialization.
const DontWipe ShouldWipe = false

// Initialize establishes a connection to the database.
// If Wipe is given, then the database will be dropped
// during initialization. Otherwise, the database is left
// as is.
func Initialize(wipe ShouldWipe, dir string) {
	var err error
	lock = sync.Mutex{}
	fqdn := path.Join(dir, DBName)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}
	db, err = sql.Open(driver, fqdn)
	if err != nil {
		log.Panic(err)
	}
	if wipe {
		for _, drop := range dropTables {
			if err := ExecuteTransactionalDDL(drop); err != nil {
				log.Panic(err)
			}
		}
	}
	for _, create := range createTables {
		if err := ExecuteTransactionalDDL(create); err != nil {
			log.Panic(err)
		}
	}
}

// ExecuteTransactionalDDL performs the provided DDL query within a transaction.
func ExecuteTransactionalDDL(query string, args ...interface{}) error {
	transaction, err := db.Begin()
	defer transaction.Commit()
	if err != nil {
		return err
	}
	stmt, err := transaction.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	if _, err := stmt.Exec(args...); err != nil {
		transaction.Rollback()
		return err
	}
	return nil
}

// ExecuteQueryOrPanicIntermediate executes a SQL query on an intermediate cert
// table. Panics on error.
func ExecuteQueryOrPanicIntermediate(query string, args ...interface{}) []Intermediate {
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	certs := make([]Intermediate, 0)
	for rows.Next() {
		cert := Intermediate{}
		err := rows.Scan(&cert.PEMInfo,
			&cert.SHA1Fingerprint,
			&cert.SHA256Fingerprint,
			&cert.CertificateID,
			&cert.CertificateIssuerCommonName,
			&cert.CertificateIssuerOrganization,
			&cert.CertificateIssuerOrganizationalUnit,
			&cert.PublicKeyAlgorithm,
			&cert.CertificateSerialNumber,
			&cert.SignatureHashAlgorithm,
			&cert.CertificateSubjectCommonName,
			&cert.CertificateSubjectOrganization,
			&cert.ValidFromGMT,
			&cert.ValidToGMT,
			&cert.CRLURLs,
			&cert.ExtendedKeyUsage,
			&cert.TechnicallyConstrained)
		if err != nil {
			log.Fatal(err)
		}
		certs = append(certs, cert)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	return certs
}

// ExecuteQueryOrPanicRoot executes a SQL query on root cert
// table. Panics on error.
func ExecuteQueryOrPanicRoot(query string, args ...interface{}) []Root {
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	certs := make([]Root, 0)
	for rows.Next() {
		cert := Root{}
		err := rows.Scan(&cert.CAOwner,
			&cert.RootCertificateName,
			&cert.CertificateIssuerCommonName,
			&cert.CertificateIssuerOrganization,
			&cert.CertificateIssuerOrganizationalUnit,
			&cert.CertificateSubjectCommonName,
			&cert.CertificateSubjectOrganization,
			&cert.CertificateSubjectOrganizationUnit,
			&cert.Subject,
			&cert.ValidFromGMT,
			&cert.ValidToGMT,
			&cert.CertificateSerialNumber,
			&cert.SignatureHashAlgorithm,
			&cert.PublicKeyAlgorithm,
			&cert.SHA1Fingerprint,
			&cert.SHA256Fingerprint,
			&cert.CertificateID,
			&cert.PEMInfo)
		if err != nil {
			log.Fatal(err)
		}
		certs = append(certs, cert)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	return certs
}
