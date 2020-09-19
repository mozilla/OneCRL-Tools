/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package kinto

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mozilla/OneCRL-Tools/kinto/api"

	"github.com/mozilla/OneCRL-Tools/kinto/api/authz"

	"github.com/mozilla/OneCRL-Tools/kinto/api/auth"
	"github.com/mozilla/OneCRL-Tools/kinto/api/batch"
	"github.com/mozilla/OneCRL-Tools/kinto/api/buckets"
	"github.com/mozilla/OneCRL-Tools/kinto/api/collections"
)

func NewOneCRL() *OneCRLCollection {
	return &OneCRLCollection{
		Collection: collections.NewCollection(buckets.NewBucket("security-state"), "onecrl"),
		Data:       []OneCRLRecord{},
	}
}

type OneCRLCollection struct {
	*collections.Collection `json:"-"`
	Data                    []OneCRLRecord `json:"data"`
}

type OneCRLRecord struct {
	Schema       int     `json:"schema"`
	Details      Details `json:"details"`
	Enabled      bool    `json:"enabled"`
	IssuerName   string  `json:"issuerName,omitempty"`
	SerialNumber string  `json:"serialNumber,omitempty"`
	Subject      string  `json:"subject,omitempty"`
	PubKeyHash   string  `json:"pubKeyHash,omitempty"`
	*api.Record
}

type Details struct {
	Bug     string `json:"bug"`
	Who     string `json:"who"`
	Why     string `json:"why"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

var Production = NewClient("https", "firefox.settings.services.mozilla.com", "/v1")

var dev = &auth.User{
	Username: "superDev",
	Password: "password",
}
var admin = &auth.User{
	Username: "admin",
	Password: "password",
}
var local = NewClient("http", "localhost:8888", "/v1").WithAuthenticator(dev)

var devRW = &authz.Permissions{
	Read:  []string{"account:superDev"},
	Write: []string{"account:superDev"},
}

func TestMain(m *testing.M) {
	if testing.Short() {
		t.Skip("Skipping docker end-to-end test because -short")
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	dir := filepath.Join(cwd, "local")
	down := exec.Command("docker-compose", "down")
	down.Dir = dir
	out, err := down.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("KINTO_TESTDIR: '%s', Output: '%s', Error:'%v'", dir, string(out), err))
	}
	up := exec.Command("docker-compose", "up")
	up.Dir = dir
	err = up.Start()
	if err != nil {
		panic(err)
	}
	start := time.Now()
	for !local.Alive() {
		time.Sleep(time.Millisecond * 200)
		if time.Now().Sub(start) > time.Minute {
			panic("took more than ten seconds to docker-compose up")
		}
	}
	local.WithAuthenticator(&auth.Unauthenticated{})
	err = local.NewAdmin(admin.Password)
	if err != nil {
		panic(err)
	}
	local.WithAuthenticator(admin)
	err = local.NewAccount(dev)
	if err != nil {
		panic(err)
	}
	oneCRL := NewOneCRL()
	err = local.NewBucketWithPermissions(oneCRL.Bucket, devRW)
	if err != nil {
		panic(err)
	}
	err = local.NewCollectionWithPermissions(oneCRL.Collection, devRW)
	if err != nil {
		panic(err)
	}
	CopyProd()

	signer := buckets.NewBucket("to_sign")
	err = local.NewBucketWithPermissions(signer, devRW)
	if err != nil {
		panic(err)
	}
	signedOnecrl := collections.NewCollection(signer, "signedOnecrl")
	err = local.NewCollectionWithPermissions(signedOnecrl, devRW)
	if err != nil {
		panic(err)
	}

	signed := buckets.NewBucket("signed")
	err = local.NewBucketWithPermissions(signed, devRW)
	if err != nil {
		panic(err)
	}
	signedOnecrl = collections.NewCollection(signed, "signedOnecrl")
	err = local.NewCollectionWithPermissions(signedOnecrl, devRW)
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func CopyProd() {
	oneCRL := NewOneCRL()
	err := Production.AllRecords(oneCRL)
	if err != nil {
		panic(err)
	}
	records := make([]interface{}, len(oneCRL.Data))
	for i, record := range oneCRL.Data {
		records[i] = record
	}
	max, err := local.BatchMaxRequests()
	if err != nil {
		panic(err)
	}
	batches := batch.NewBatches(records, max, devRW, http.MethodPost, oneCRL.Get())
	for _, b := range batches {
		err = local.Batch(b)
		if err != nil {
			panic(err)
		}
	}
	l := NewOneCRL()
	p := NewOneCRL()
	err = local.AllRecords(l)
	if err != nil {
		panic(err)
	}
	err = Production.AllRecords(p)
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(l.Data, p.Data) {
		panic(fmt.Sprintf("production and local did not match each other.\ngot: %v\nwant: %v", l.Data, p.Data))
	}
}

func TestKintoSigner(t *testing.T) {
	signer := buckets.NewBucket("to_sign")
	onecrl := collections.NewCollection(signer, "signedOnecrl")
	record := &OneCRLRecord{
		IssuerName: "honest achmed's",
	}
	err := local.NewRecord(onecrl, record)
	if err != nil {
		t.Fatal(err)
	}
	status, err := local.SignerStatusFor(onecrl)
	if err != nil {
		t.Fatal(err)
	}
	if status.InReview() {
		t.Fatal("collection is unexpectedly in review")
	}
	err = local.ToReview(onecrl)
	if err != nil {
		t.Fatal(err)
	}
	status, err = local.SignerStatusFor(onecrl)
	if !status.InReview() {
		t.Fatal("collection is unexpectedly not in review")
	}
	err = local.ToSign(onecrl)
	if err != nil {
		t.Fatal(err)
	}
	err = local.ToSigned(onecrl)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewRecord(t *testing.T) {
	record := &OneCRLRecord{
		IssuerName: "honest achmed's",
	}
	err := local.NewRecord(NewOneCRL(), record)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRecord(t *testing.T) {
	o := NewOneCRL()
	record := &OneCRLRecord{
		IssuerName: "honest achmed's",
	}
	err := local.NewRecord(o, record)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := local.Delete(o, record)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Data.Deleted {
		t.Fatalf("kinto deletion response says that '%s' was not deleted", record.ID())
	}
	err = local.AllRecords(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range o.Data {
		if r.ID() == record.ID() {
			t.Fatalf("expected '%s' to be deleted but it was not", r.ID())
		}
	}
}

func TestPatchRecord(t *testing.T) {
	record := &OneCRLRecord{
		IssuerName: "Honest Achmed's",
		Details: Details{
			Why: "dunno, seemed like a good guy",
		},
	}
	err := local.NewRecord(NewOneCRL(), record)
	if err != nil {
		t.Fatal(err)
	}
	if record.Record == nil {
		t.Fatal("Failed to deserialize return structure")
	}
	record.Details.Bug = "https://bugzilla.mozilla.org/show_bug.cgi?id=647959"
	err = local.UpdateRecord(NewOneCRL(), record)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetOneCRL(t *testing.T) {
	err := local.AllRecords(NewOneCRL())
	if err != nil {
		t.Fatal(err)
	}
}

func TestTryAuth(t *testing.T) {
	c := NewClient("http", "localhost:8888", "/v1").WithAuthenticator(admin)
	authed, err := c.TryAuth()
	if err != nil {
		t.Fatal(err)
	}
	if !authed {
		t.Fatal("expected to be authenticated")
	}
}

func TestTryAuthFail(t *testing.T) {
	c := NewClient("http", "localhost:8888", "/v1").WithAuthenticator(&auth.User{
		Username: "chris",
		Password: "nyope",
	})
	authed, err := c.TryAuth()
	if err != nil {
		t.Fatal(err)
	}
	if authed {
		t.Fatal("expected to be unauthenticated")
	}
}

func TestNewAccount(t *testing.T) {
	c := NewClient("http", "localhost:8888", "/v1").WithAuthenticator(admin)
	err := c.NewAccount(&auth.User{Username: "chris", Password: "password1234"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewBucket(t *testing.T) {
	b := buckets.NewBucket("security-state")
	err := local.NewBucketWithPermissions(b, devRW)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewCollection(t *testing.T) {
	bucket := buckets.NewBucket("security-state")
	collection := collections.NewCollection(bucket, "onecrl")
	err := local.NewCollectionWithPermissions(collection, devRW)
	if err != nil {
		t.Fatal(err)
	}
}
