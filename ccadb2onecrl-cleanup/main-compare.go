package main

import (
	"fmt"
	"log"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL-cleanup/ccadb"
	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL-cleanup/onecrl"
)

// RemoveExpiredCertsFromOneCRL fetches expired certificates from CCADB,
// removes them from OneCRL, and updates CCADB to reflect the removal.
func RemoveExpiredCertsFromOneCRL() error {
	fmt.Println("Starting cleanup of expired certificates from OneCRL...")

	// Step 1: Fetch certificates flagged as "Cert Expired" from CCADB
	expiredCerts, err := ccadb.FetchExpiredCertificates()
	if err != nil {
		log.Fatalf("Failed to fetch expired certificates from CCADB: %v", err)
		return err
	}

	if len(expiredCerts) == 0 {
		fmt.Println("No expired certificates to remove.")
		return nil
	}

	// Step 2: Remove certificates from OneCRL
	for _, cert := range expiredCerts {
		err := onecrl.RemoveCertificate(cert)
		if err != nil {
			log.Printf("Failed to remove certificate %s from OneCRL: %v", cert.SerialNumber, err)
			continue
		}
		fmt.Printf("Successfully removed certificate %s from OneCRL\n", cert.SerialNumber)

		// Step 3: Update CCADB status to "Removed from OneCRL"
		err = ccadb.UpdateCertificateStatus(cert, "Removed from OneCRL")
		if err != nil {
			log.Printf("Failed to update CCADB status for %s: %v", cert.SerialNumber, err)
		}
	}

	fmt.Println("Cleanup process completed.")
	return nil
}

func main() {
	if err := RemoveExpiredCertsFromOneCRL(); err != nil {
		log.Fatalf("Error during cleanup process: %v", err)
	}
}
