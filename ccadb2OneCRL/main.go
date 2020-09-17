/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main // import "github.com/mozilla/OneCRL-Tools/ccadb2OneCRL"
import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/mozilla/OneCRL-Tools/kinto/api/auth"

	bugzAuth "github.com/mozilla/OneCRL-Tools/bugzilla/api/auth"

	"github.com/pkg/errors"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/attachments"

	bugzilla "github.com/mozilla/OneCRL-Tools/bugzilla/client"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/bugs"

	"github.com/mozilla/OneCRL-Tools/transaction"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/kinto"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/ccadb"
	log "github.com/sirupsen/logrus"
)

const (
	// Base URL for Kinto production [default: "https://settings.prod.mozaws.net/v1"]
	OneCRLProduction        = "ONECRL_PRODUCTION"
	oneCRLProductionDefault = "https://settings.prod.mozaws.net/v1"
	// User account for Kinto production. Requires OneCRLProductionPassword to be set. Mutually exclusive with OneCRLProductionToken.
	OneCRLProductionUser = "ONECRL_PRODUCTION_USER"
	// User password for Kinto production. Requires OneCRLProductionUser to be set. Mutually exclusive with OneCRLProductionToken.
	OneCRLProductionPassword = "ONECRL_PRODUCTION_PASSWORD"
	// Auth token for Kinto production. Mutually exclusive with OneCRLProductionUser and OneCRLProductionPassword.
	OneCRLProductionToken = "ONECRL_PRODUCTION_TOKEN"
	// Target production bucket [default: "security-state-staging"]
	OneCRLProductionBucket = "ONECRL_PRODUCTION_BUCKET"
	// Target production collection [default: "onecrl"]
	// Default is likely what you want as this is mostly configurable for testing purposes.
	OneCRLProductionCollection = "ONECRL_PRODUCTION_COLLECTION"
	// Base URL for Kinto production [default: "https://settings.stage.mozaws.net/v1"]
	OneCRLStaging        = "ONECRL_STAGING"
	oneCRLStagingDefault = "https://settings.stage.mozaws.net/v1"
	// User account for Kinto staging. Requires OneCRLStagingPassword to be set. Mutually exclusive with OneCRLStagingToken.
	OneCRLStagingUser = "ONECRL_STAGING_USER"
	// User password for Kinto staging. Requires OneCRLStagingUser to be set. Mutually exclusive with OneCRLStagingToken.
	OneCRLStagingPassword = "ONECRL_STAGING_PASSWORD"
	// Auth token for Kinto staging. Mutually exclusive with OneCRLStagingUser and OneCRLStagingPassword.
	OneCRLStagingToken = "ONECRL_STAGING_TOKEN"
	// Target staging bucket [default: "security-state-staging"].
	// Default is likely what you want as this is mostly configurable for testing purposes.
	OneCRLStagingBucket = "ONECRL_STAGING_BUCKET"
	// Target staging collection [default: "onecrl"]
	// Default is likely what you want as this is mostly configurable for testing purposes.
	OneCRLStagingCollection = "ONECRL_STAGING_COLLECTION"
	// Base URL for Bugzilla [default: "https://bugzilla.mozilla.org"]
	Bugzilla        = "BUGZILLA"
	bugzillaDefault = "https://bugzilla.mozilla.org"
	// Mandatory API key for posting to Bugzilla. This key MUST have write permissions.
	BugzillaApiKey = "BUGZILLA_API_KEY"
	// Optional. A comma separated list of of email accounts to put on CC for new bugs. If these accounts are not
	// registered with the configured Bugzilla, then a runtime error will occur when creating new bugs.
	BugzillaCcAccounts = "BUGZILLA_CC_ACCOUNTS"
	// Target logging level for this tool.
	//	Available: panic, fatal, error, warn, warning info, debug, trace
	//	Default: info
	LogLevel = "LOG_LEVEL"
	// Target directory for logs. Each run of the tool will be logged to the timestamp
	// of when it was ran. [default: stdout/stderr]
	LogDir = "LOG_DIR"
)

func main() {
	config := filepath.Join(filepath.Dir(os.Args[0]), "config.env")
	if len(os.Args) > 1 {
		config = os.Args[1]
	}
	err := godotenv.Load(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config.env appears to be malformed, err: %v\n", err)
		os.Exit(1)
	}
	_main()
}

// _main is just a unit testable main (since main is looking at command line args
// and loading configs from the filesyste it's not a great target for testing).
func _main() {
	err := SetLogOut()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to set logging out file, err: %v\n", err)
		os.Exit(1)
	}
	level, err := ParseLogLevel()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "unexpected logging level %s\n", os.Getenv(LogLevel))
		_, _ = fmt.Fprint(os.Stderr, "expected one of either panic, fatal, error, warn, warning info, debug, trace")
		os.Exit(1)
	}
	log.SetLevel(level)
	// This gets us call site information, which is rather useful. It is also the reason
	// why we need to compile with go >= 1.15 (logrus needed a newer runtime API in order to pull it off, apparently).
	log.SetReportCaller(true)
	log.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
	production, err := Production()
	if err != nil {
		log.WithField("production", os.Getenv(OneCRLProduction)).
			WithError(err).
			Fatal("failed to construct OneCRL production client")
	}
	staging, err := Staging()
	if err != nil {
		log.WithError(err).
			Fatal("failed to construct OneCRL staging client")
	}
	bugz := BugzillaClient()
	updater := NewUpdate(staging, production, bugz)
	err = updater.Update()
	if err != nil {
		log.WithError(err).Error("update failed")
		os.Exit(1)
	}
	log.Info("update completed")
}

// Production returns a Kinto client that is configured to target
// the OneCRLProduction class of environment variable.
func Production() (*kinto.Client, error) {
	production := oneCRLProductionDefault
	if os.Getenv(OneCRLProduction) != "" {
		production = os.Getenv(OneCRLProduction)
	}
	c, err := kinto.NewClientFromStr(production)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct OneCRL production client from URL")
	}
	principal, err := KintoPrincipal(
		os.Getenv(OneCRLProductionUser),
		os.Getenv(OneCRLProductionPassword),
		os.Getenv(OneCRLProductionToken))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set OneCRL production credentials")
	}
	return c.WithAuthenticator(principal), nil
}

// Staging returns a Kinto client that is configured to target
// the OneCRLStaging class of environment variable.
func Staging() (*kinto.Client, error) {
	staging := oneCRLStagingDefault
	if os.Getenv(OneCRLStaging) != "" {
		staging = os.Getenv(OneCRLStaging)
	}
	c, err := kinto.NewClientFromStr(staging)
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct OneCRL staging client from URL")
	}
	principal, err := KintoPrincipal(
		os.Getenv(OneCRLStagingUser),
		os.Getenv(OneCRLStagingPassword),
		os.Getenv(OneCRLStagingToken))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set OneCRL staging credentials")
	}
	return c.WithAuthenticator(principal), nil
}

func ProductionCollection() *onecrl.OneCRL {
	return Collection(os.Getenv(OneCRLProductionBucket), os.Getenv(OneCRLProductionCollection))
}

func StagingCollection() *onecrl.OneCRL {
	return Collection(os.Getenv(OneCRLStagingBucket), os.Getenv(OneCRLStagingCollection))
}

func Collection(bucket, collection string) *onecrl.OneCRL {
	o := onecrl.NewOneCRL()
	if bucket != "" {
		o.Bucket.ID = bucket
	}
	if collection != "" {
		o.ID = collection
	}
	return o
}

// KintoPrincipal returns an appropriate authenticator based on the input.
//
// If a username and password is provided, then an auth.User will be returned.
// If a token is provided, then an auth.Token will be returned.
//
// All other combinations will result in an error.
func KintoPrincipal(user, password, token string) (auth.Authenticator, error) {
	if user == "" && password == "" && token == "" {
		return &auth.Unauthenticated{}, nil
	}
	if user != "" && password != "" && token != "" ||
		user == "" && password != "" ||
		user != "" && password == "" {
		return nil, fmt.Errorf("an invalid combination of 'user', 'password', and 'token' was set")
	}
	if token != "" {
		return &auth.Token{Token: token}, nil
	}
	return &auth.User{Username: user, Password: password}, nil
}

func BugzillaClient() *bugzilla.Client {
	bugz := bugzillaDefault
	if os.Getenv(Bugzilla) != "" {
		bugz = os.Getenv(Bugzilla)
	}
	return bugzilla.NewClient(bugz).
		WithAuth(&bugzAuth.ApiKey{ApiKey: os.Getenv(BugzillaApiKey)})
}

func ParseLogLevel() (log.Level, error) {
	l := os.Getenv(LogLevel)
	if l == "" {
		return log.InfoLevel, nil
	}
	return log.ParseLevel(l)
}

func SetLogOut() error {
	logDir := os.Getenv(LogDir)
	if logDir == "" {
		// Use stdout/stderr
		return nil
	}
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(filepath.Join(logDir, time.Now().UTC().Format(time.RFC3339)))
	if err != nil {
		return err
	}
	log.SetOutput(out)
	return nil
}

// Updater is all of the state necessary to keep track of a SINGLE round of updates.
// It is not intended to be reused (although it could be with a bit of modification).
type Updater struct {
	changes    []*onecrl.Record
	bugID      int
	staging    *kinto.Client
	production *kinto.Client
	bugzilla   *bugzilla.Client
}

func NewUpdate(staging, production *kinto.Client, bugz *bugzilla.Client) *Updater {
	return &Updater{
		staging:    staging,
		production: production,
		bugzilla:   bugz,
	}
}

// Update is the main entry point to the core business logic.
func (u *Updater) Update() error {
	// Do some canary tests against Kinto to make sure that
	// we are properly authenticated for both production and
	// staging before we move on with anything.
	err := u.TryAuth()
	if err != nil {
		return err
	}
	// Policy is that if staging is in review then we bail
	// out of this operation early and send out emails.
	inReview, err := u.StagingIsInReview()
	if err != nil {
		return err
	}
	if inReview {
		log.Info("staging is in review")
		// We want to find the intersection between the CCADB
		// and OneCRL as those are the revocations that are still
		// in review. Once we find them we would like to post
		// gentle reminders to the associated Bugzilla tickets.
		intersection, err := u.FindIntersection()
		if err != nil {
			return err
		}
		u.BlastEmails(intersection)
		return nil
	}
	err = u.FindDiffs()
	if err != nil {
		return err
	}
	if u.NoDiffs() {
		log.Info("no differences found between the CCADB and OneCRL staging/production")
		return nil
	}
	// From here on we begin mutating datasets (OneCRL staging/production and Bugzilla)
	// so we would like to put these actions into a transactional context. Ideally,
	// each step should be able to undo itself if necessary.
	err = transaction.Start().
		Then(u.PushToStaging()).
		Then(u.OpenBug()).
		Then(u.UpdateRecordsWithBugID()).
		Then(u.PutStagingIntoReview()).
		Then(u.PushToProduction()).
		AutoRollbackOnError(true).
		AutoClose(true).
		Commit()
	if err == nil {
		log.WithField("bugzilla", u.bugzilla.ShowBug(u.bugID)).Info("successfully completed update")
	}
	return err
}

// TryAuth attempts the "try_authentication" Kinto API for first staging and then production.
//
// For more information on the Kinto API, please see https://docs.kinto-storage.org/en/stable/api/1.x/authentication.html#try-authentication
func (u *Updater) TryAuth() error {
	var err error = nil
	ok, e := u.staging.TryAuth()
	if e != nil {
		err = e
	} else if !ok {
		err = fmt.Errorf("authentication for staging Kinto failed")
	}
	ok, e = u.production.TryAuth()
	if e != nil {
		if err != nil {
			err = errors.Wrap(err, e.Error())
		} else {
			err = e
		}
	} else if !ok {
		if err != nil {
			err = errors.Wrap(err, "authentication for production Kinto failed")
		} else {
			err = fmt.Errorf("authentication for production Kinto failed")
		}
	}
	// If err == nil then WithStack returns nil.
	return errors.WithStack(err)
}

// FindDiffs finds all entries that are within the CCADB
// that are not within OneCRL. Each entry found constructs
// an appropriate onecrl.Record entry and emplaces it in
// u.records for future reference.
func (u *Updater) FindDiffs() error {
	oneCRL, c, err := u.getDataSets()
	if err != nil {
		return err
	}
	diffs := c.Difference(oneCRL)
	u.changes = make([]*onecrl.Record, 0)
	for diff := range diffs.Iter() {
		record, err := onecrl.FromCCADB(diff.(*ccadb.Certificate))
		if err != nil {
			return errors.WithStack(err)
		}
		u.changes = append(u.changes, record)
	}
	return nil
}

// FindIntersection finds the intersection between
// union(oneCRLProd, oneCRLStag) and the CCADB.
func (u *Updater) FindIntersection() (*onecrl.Set, error) {
	oneCRL, ccadb, err := u.getDataSets()
	if err != nil {
		return nil, err
	}
	return oneCRL.Intersection(ccadb).(*onecrl.Set), nil
}

// getDataSets return the union(oneCRLProd, oneCRLStag) and the CCADB.
func (u *Updater) getDataSets() (*onecrl.Set, *ccadb.Set, error) {
	production := ProductionCollection()
	err := u.production.AllRecords(production)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	productionSet := onecrl.NewSetFrom(production)
	/////////
	staging := StagingCollection()
	err = u.staging.AllRecords(staging)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	stagingSet := onecrl.NewSetFrom(staging)
	//////
	oneCRLUnion := productionSet.Union(stagingSet).(*onecrl.Set)
	//////
	ccadbRecords, err := ccadb.Default()
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	ccadbSet := ccadb.NewSetFrom(ccadbRecords)
	return oneCRLUnion, ccadbSet, nil
}

func (u *Updater) NoDiffs() bool {
	return len(u.changes) == 0
}

func (u *Updater) StagingIsInReview() (bool, error) {
	status, err := u.staging.SignerStatusFor(StagingCollection())
	if err != nil {
		return false, errors.WithStack(err)
	}
	return status.InReview(), nil
}

func (u *Updater) PushToStaging() transaction.Transactor {
	committed := 0
	return transaction.NewTransaction().WithCommit(func() error {
		collection := StagingCollection()
		for _, record := range u.changes {
			err := u.staging.NewRecord(collection, record)
			if err != nil {
				return errors.WithStack(err)
			}
			committed += 1
		}
		return nil
	}).WithRollback(func(_ error) error {
		// Try to delete as many of the entries that we can that
		// WERE successfully inserted. Single error while deleting
		// does not fail out the entire rollback, so it is possible
		// for this rollback to leave orphaned data on staging
		// the service is degraded and only sporadically failing.
		var err error = nil
		collection := StagingCollection()
		for i := 0; i < committed; i++ {
			_, e := u.staging.Delete(collection, u.changes[i])
			if e != nil {
				if err == nil {
					err = e
				} else {
					err = errors.Wrap(err, e.Error())
				}
			}
		}
		return errors.WithStack(err)
	})
}

// I think this speaks for itself, it's a crumby little integration complication.
const attachmentWarning = "received an error while uploading an attachment to BugzillaClient, however " +
	"a 'Failed to fetch attachment ID <ID> from S3' error always occurs when attaching a bug. This is " +
	"likely just a synchronization bug wherein BugzillaClient saves a record to S3 and then immediately attempts " +
	"to retrieve it, however S3 has not published the ID yet. If that is this error, then please " +
	"ignore it."

// OpenBug creates a new ticket in Bugzilla. The bug will have attached to it
// a file containing line delimited issuer:serial pairs, a file the proposed
// JSON insertion into OneCRL, and a file which shows the CCADB representation
// as well as the OneCRL representation side-by-side.
//
// If configured, then emails in BugzillaCcAccounts will be put on CC.
func (u *Updater) OpenBug() transaction.Transactor {
	u.bugID = -1
	return transaction.NewTransaction().WithCommit(func() error {
		// Human readable, line delimited, "issuer: %s serial: %s"
		issuerSerialPairs := ""
		proposedAdditions := make([]*onecrl.Record, 0)
		for _, record := range u.changes {
			issuerSerialPairs += fmt.Sprintf("issuer: %s serial: %s\n", record.IssuerName, record.SerialNumber)
			proposedAdditions = append(proposedAdditions, record)
		}
		// Try to read the environment variable that declares a list of Bugzilla accounts to put on CC.
		_cc, err := csv.NewReader(strings.NewReader(os.Getenv(BugzillaCcAccounts))).ReadAll()
		if err != nil {
			log.WithError(err).
				WithField("BugzillaCcAccounts", os.Getenv(BugzillaCcAccounts)).
				Error("the CC environment variable appears to be malformed")
			return err
		}
		// The CSV parser is always going to return a [][]string, but really
		// we only want the first "row".
		var cc []string = nil
		if len(_cc) > 0 {
			cc = _cc[0]
			log.WithField("CC", cc).Debug("using CC environment variable")
		}
		bug := &bugs.Create{
			Product:     "Toolkit",
			Component:   "Blocklist Policy Requests",
			Summary:     fmt.Sprintf("CCADB entries generated %s", time.Now().UTC().Format(time.RFC3339)),
			Version:     "unspecified",
			Severity:    "normal",
			Type:        "enhancement",
			Description: "Adding entries to OneCRL based on revoked intermediate certificates reported in the CCADB.",
			Cc:          cc,
		}
		log.WithField("payload", bug).Debug("sending bugzilla creation payload")
		resp, err := u.bugzilla.CreateBug(bug)
		if err != nil {
			log.WithError(err).Error("bugzilla create failed")
			return errors.WithStack(err)
		}
		log.WithField("id", resp.Id).
			WithField("url", u.bugzilla.ShowBug(resp.Id)).
			Debug("created bugzilla ticket")
		u.bugID = resp.Id
		for _, record := range u.changes {
			record.Details.Bug = u.bugzilla.ShowBug(u.bugID)
		}
		log.WithField("issuerSerialPairs", issuerSerialPairs).Debug("attempting to post issuer/serial pairs")
		_, err = u.bugzilla.CreateAttachment((&attachments.Create{
			BugId:       resp.Id,
			Data:        []byte(issuerSerialPairs),
			FileName:    "BugData.txt",
			Summary:     "Line delimited issuer/serial pairs",
			ContentType: "text/plain",
		}).AddBug(resp.Id))
		if err != nil {
			log.WithError(err).WithField("attachment", "BugData.txt").Warn(attachmentWarning)
		}
		additions, err := json.MarshalIndent(proposedAdditions, "", "  ")
		log.WithField("additions", proposedAdditions).Debug("attempting to post proposed OneCRL additions")
		if err != nil {
			return errors.WithStack(err)
		}
		_, err = u.bugzilla.CreateAttachment((&attachments.Create{
			BugId:       resp.Id,
			Data:        additions,
			FileName:    "OneCRLAdditions.txt",
			Summary:     "The additions to OneCRL proposed by this bug.",
			ContentType: "text/plain",
		}).AddBug(resp.Id))
		if err != nil {
			log.WithError(err).WithField("attachment", "OneCRLAdditions.txt").Warn(attachmentWarning)
		}
		comparisons := make([]interface{}, 0)
		for _, record := range u.changes {
			d, err := record.ToComparison()
			if err != nil {
				log.WithField("record", record).
					WithError(err).
					Error("failed to generate a OneCRL/CCADB comparison")
				return errors.WithStack(err)
			}
			comparisons = append(comparisons, d)
		}
		d, err := json.MarshalIndent(comparisons, "", "  ")
		if err != nil {
			return errors.WithStack(err)
		}
		log.WithField("comparison", comparisons).Debug("attempting to post OneCRL/CCADB comparison")
		_, err = u.bugzilla.CreateAttachment((&attachments.Create{
			BugId:       resp.Id,
			Data:        d,
			FileName:    "DecodedEntries.txt",
			Summary:     "Entries with their names decoded to plain text and hexadecimal serials/hashes.",
			ContentType: "text/plain",
		}).AddBug(resp.Id))
		if err != nil {
			log.WithError(err).WithField("attachment", "DecodedEntries.txt").Warn(attachmentWarning)
		}
		return nil
	}).WithRollback(func(cause error) error {
		if u.bugID == -1 {
			return nil
		}
		report := &strings.Builder{}
		logger := log.New()
		logger.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
		logger.SetOutput(report)
		logger.WithError(cause).
			WithField("stacktrace", fmt.Sprintf("%+v", cause)). // "%+v" gets us a stack trace printed out
			Error("This tool experienced a fatal error downstream of posting this bug. This bug will be " +
				"closed. Please review the provided cause and call site of the cause for more information.")
		log.WithError(cause).WithField("bugzilla", u.bugzilla.ShowBug(u.bugID)).Error("closing the listed " +
			"bug due to a critical failure")
		_, err := u.bugzilla.UpdateBug(bugs.Invalidate(u.bugID, report.String()))
		return errors.WithStack(err)
	})
}

// After we have created the bug in question on Bugzilla, we need to go back to
// staging and update the records with the Bugzilla ID.
func (u *Updater) UpdateRecordsWithBugID() transaction.Transactor {
	return transaction.NewTransaction().WithCommit(func() error {
		collection := StagingCollection()
		for _, record := range u.changes {
			if record == nil {
				continue
			}
			err := u.staging.UpdateRecord(collection, record)
			if err != nil {
				return errors.WithStack(err)
			}
		}
		return errors.WithStack(u.staging.ToSign(collection))
	}).WithRollback(func(_ error) error {
		// Upstream transactions are going to delete these changes
		// anyways, so I don't really see much of anything to do here.
		return nil
	})
}

func (u *Updater) PutStagingIntoReview() transaction.Transactor {
	return transaction.NewTransaction().WithCommit(func() error {
		return errors.WithStack(u.staging.ToReview(StagingCollection()))
	}).WithRollback(func(_ error) error {
		return errors.WithStack(u.staging.ToRollBack(StagingCollection()))
	})
}

func (u *Updater) PushToProduction() transaction.Transactor {
	return transaction.NewTransaction().WithCommit(func() error {
		collection := ProductionCollection()
		for _, record := range u.changes {
			// If we do not set the ID back to default then production will
			// end up having IDs that were generated by staging rather than itself.
			record.Id = ""
			err := u.production.NewRecord(collection, record)
			if err != nil {
				return errors.WithStack(err)
			}
		}
		return nil
	})
}

func (u *Updater) BlastEmails(intersection *onecrl.Set) {
	bugIDs := make(map[int]bool, 0)
	builder := strings.Builder{}
	builder.WriteString("Staging is in review. The following bugs appear to require resolution.\n")
	for e := range intersection.Iter() {
		entry := e.(*onecrl.Record)
		id, err := u.bugzilla.IDFromShowBug(entry.Details.Bug)
		if err != nil {
			log.WithError(err).
				WithField("url", entry.Details.Bug).
				Error("failed to retrieve bugzilla ID number from URL")
			continue
		}
		if bugIDs[id] {
			continue
		}
		builder.WriteByte('\t')
		builder.WriteString(entry.Details.Bug)
		bugIDs[id] = true
	}
	for id := range bugIDs {
		_, err := u.bugzilla.UpdateBug(&bugs.Update{
			Id:      id,
			Ids:     []int{id},
			Comment: &bugs.Comment{Body: builder.String()},
		})
		if err != nil {
			log.WithError(err).WithField("ID", id).Warn("failed to ping blocking bug")
		}
	}
}
