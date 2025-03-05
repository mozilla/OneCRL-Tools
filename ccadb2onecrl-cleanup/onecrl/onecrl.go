/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package onecrl


import (
	"fmt"
	"github.com/mozilla/OneCRL-Tools/kinto/api/collections"
	log "github.com/sirupsen/logrus"
	"github.com/pkg/errors"
)

// RemoveCertificate removes a certificate from OneCRL.
func RemoveCertificate(cert *Certificate) error {
	log.Printf("Removing certificate %s from OneCRL...", cert.SerialNumber)

	collection := collections.NewCollection("security-state-staging", "onecrl")
	err := collection.DeleteRecord(cert.SerialNumber)
	if err != nil {
		return errors.Wrapf(err, "failed to remove certificate %s from OneCRL", cert.SerialNumber)
	}

	log.Printf("Successfully removed certificate %s from OneCRL.", cert.SerialNumber)
	return nil
}
