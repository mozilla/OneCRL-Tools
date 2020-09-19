/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/mozilla/OneCRL-Tools/kinto/api/auth"
	"github.com/mozilla/OneCRL-Tools/kinto/api/authz"
	"github.com/mozilla/OneCRL-Tools/kinto/api/batch"

	"github.com/mozilla/OneCRL-Tools/ccadb2OneCRL/onecrl"
	"github.com/mozilla/OneCRL-Tools/kinto"
)

func TestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping docker end-to-end test because -short")
		return
	}

	setup()
	c, err := godotenv.Unmarshal(testConfig)
	if err != nil {
		panic(err)
	}
	for k, v := range c {
		err = os.Setenv(k, v)
		if err != nil {
			panic(err)
		}
	}
	_main()
}

var dev = &auth.User{
	Username: "superDev",
	Password: "password",
}
var admin = &auth.User{
	Username: "admin",
	Password: "password",
}

var devRW = &authz.Permissions{
	Write: []string{"account:superDev"},
	Read:  []string{"system.Everyone"},
}

var local = kinto.NewClient("http", "localhost:8888", "/v1").WithAuthenticator(dev)
var staging = kinto.NewClient("https", "settings.stage.mozaws.net", "/v1")
var production = kinto.NewClient("https", "firefox.settings.services.mozilla.com", "/v1")

func setup() {
	makeLocal()
	syncStaging()
	syncProduction()
}

func syncStaging() {
	dataA := onecrl.NewOneCRL()
	if err := staging.AllRecords(dataA); err != nil {
		panic(err)
	}
	d := make([]interface{}, len(dataA.Data))
	for i, v := range dataA.Data {
		d[i] = v
	}
	max, err := local.BatchMaxRequests()
	if err != nil {
		panic(err)
	}
	batches := batch.NewBatches(d, max, nil, http.MethodPost, dataA.Get())
	for _, b := range batches {
		if err := local.Batch(b); err != nil {
			panic(err)
		}
	}
}

func syncProduction() {
	dataA := onecrl.NewOneCRL()
	if err := production.AllRecords(dataA); err != nil {
		panic(err)
	}
	d := make([]interface{}, len(dataA.Data))
	for i, v := range dataA.Data {
		d[i] = v
	}
	max, err := local.BatchMaxRequests()
	if err != nil {
		panic(err)
	}
	dataA.Bucket.ID = "production-security-state"
	batches := batch.NewBatches(d, max, nil, http.MethodPost, dataA.Get())
	for _, b := range batches {
		if err := local.Batch(b); err != nil {
			panic(err)
		}
	}
}

func makeLocal() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	dir := filepath.Join(filepath.Dir(cwd), "kinto", "local")
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
			panic("took more than one minute to docker-compose up")
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
	oneCRL := onecrl.NewOneCRL()
	err = local.NewBucketWithPermissions(oneCRL.Bucket, devRW)
	if err != nil {
		panic(err)
	}
	err = local.NewCollectionWithPermissions(oneCRL.Collection, devRW)
	if err != nil {
		panic(err)
	}
	oneCRL.Bucket.ID = "production-security-state"
	err = local.NewBucketWithPermissions(oneCRL.Bucket, devRW)
	if err != nil {
		panic(err)
	}
	err = local.NewCollectionWithPermissions(oneCRL.Collection, devRW)
	if err != nil {
		panic(err)
	}
}

func TestKintoPrincipal(t *testing.T) {
	c, err := KintoPrincipal("chris", "itsasecret", "")
	if err != nil {
		t.Fatal()
	}
	_, ok := c.(*auth.User)
	if !ok {
		t.Fatalf("unexpected type %T", c)
	}
}

func TestKintoPrincipal2(t *testing.T) {
	c, err := KintoPrincipal("", "", "1234")
	if err != nil {
		t.Fatal()
	}
	_, ok := c.(*auth.Token)
	if !ok {
		t.Fatalf("unexpected type %T", c)
	}
}

func TestKintoPrincipal3(t *testing.T) {
	c, err := KintoPrincipal("", "", "")
	if err != nil {
		t.Fatal()
	}
	_, ok := c.(*auth.Unauthenticated)
	if !ok {
		t.Fatalf("unexpected type %T", c)
	}
}

func TestKintoPrincipal4(t *testing.T) {
	if c, err := KintoPrincipal("chris", "", ""); err == nil {
		t.Errorf("unexpected non-error return, got a %T", c)
	}
	if c, err := KintoPrincipal("", "asd", ""); err == nil {
		t.Errorf("unexpected non-error return, got a %T", c)
	}
	if c, err := KintoPrincipal("chris", "", "asd"); err == nil {
		t.Errorf("unexpected non-error return, got a %T", c)
	}
	if c, err := KintoPrincipal("", "asd", "asd"); err == nil {
		t.Errorf("unexpected non-error return, got a %T", c)
	}
	if c, err := KintoPrincipal("chris", "asd", "asd"); err == nil {
		t.Errorf("unexpected non-error return, got a %T", c)
	}
}

const testConfig = `
ONECRL_PRODUCTION="http://localhost:8888/v1"
ONECRL_PRODUCTION_USER="superDev"
ONECRL_PRODUCTION_PASSWORD="password"

ONECRL_STAGING="http://localhost:8888/v1"
ONECRL_STAGING_USER="superDev"
ONECRL_STAGING_PASSWORD="password"

ONECRL_STAGING_BUCKET="production-security-state"
ONECRL_STAGING_COLLECTION="onecrl"

BUGZILLA="https://bugzilla-dev.allizom.org"
BUGZILLA_API_KEY="PcKr3LgH6bL0WDXlPuC0wLhFTUuhT8UJSvPKF0UQ"
BUGZILLA_CC_ACCOUNTS="chris@chenderson.org"

LOG_LEVEL="trace"

LOG_DIR=/tmp/ccadb2onecrl/logs
`
