/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package config

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

const ProductionPrefix string = "https://firefox.settings.services.mozilla.com"
const StagePrefix string = "https://settings.stage.mozaws.net"
const RecordsPathPrefix string = "/v1/buckets/"
const RecordsPathSuffix string = "/collections/certificates/records"

const PREFIX_BUGZILLA_PROD string = "https://bugzilla.mozilla.org"
const PREFIX_BUGZILLA_STAGE string = "https://bugzilla.allizom.org"

type OneCRLConfig struct {
	oneCRLConfig       string
	oneCRLEnvString    string `mapstructure:"onecrlenv"`
	oneCRLBucketString string `mapstructure:"onecrlbucket"`
	OneCRLVerbose      string `mapstructure:"onecrlverbose"`
	BugzillaBase       string `mapstructure:"bugzilla"`
	BugzillaAPIKey     string `mapstructure:"bzapikey"`
	BugzillaReviewers  string `mapstructure:"reviewers"`
	BugzillaBlockee    string `mapstructure:"blockee"`
	BugDescription     string `mapstructure:"bugdescription"`
	Preview            string `mapstructure:"preview"`
	EnforceCRLChecks   string `mapstructure:"enforcecrlchecks"`
	KintoUser          string `mapstructure:"kintouser"`
	KintoPassword      string `mapstructure:"kintopass"`
	KintoCollectionURL string `mapstructure:"collectionurl"`
	AdditionalConfig   map[string]string
}

func (config OneCRLConfig) GetRecordURLForEnv(environment string) (error, string) {
	var RecordsPath string = RecordsPathPrefix + config.oneCRLBucketString + RecordsPathSuffix

	if environment == "stage" {
		return nil, StagePrefix + RecordsPath
	}
	if environment == "production" {
		return nil, ProductionPrefix + RecordsPath
	}
	return errors.New("valid onecrlenv values are \"stage\" and \"production\""), ""
}

func (config OneCRLConfig) GetRecordURL() (error, string) {
	return config.GetRecordURLForEnv(config.oneCRLEnvString)
}

const DEFAULT_ONECRLCONFIG string = ".config.yml"
const DEFAULT_ONECRLENV string = "production"
const DEFAULT_ONECRLBUCKET string = "blocklists"
const DEFAULT_ONECRLVERBOSE string = "no"
const DEFAULT_COLLECTION_URL string = "https://kinto-writer.stage.mozaws.net/v1/buckets/staging/collections/certificates"
const DEFAULT_DEFAULT string = ""
const DEFAULT_PREVIEW string = "no"
const DEFAULT_ENFORCE_CRL_CHECKS string = "yes"
const DEFAULT_DESCRIPTION string = "Here are some entries: Please ensure that the entries are correct."

func (config *OneCRLConfig) loadConfig() error {
	config_map := map[string]string{}

	// load the config from configuration file
	loaded := OneCRLConfig{}

	filename := config.oneCRLConfig
	fmt.Printf("config file was: %v\n", filename)
	if filename == DEFAULT_ONECRLCONFIG {
		env_filename := os.Getenv("onecrlconfig")
		fmt.Printf("Looking for config file in environment: %v\n", env_filename)
		if 0 != len(env_filename) {
			filename = env_filename
		}
	}
	if len(filename) == 0 {
		filename = DEFAULT_ONECRLCONFIG
	}
	data, err := ioutil.ReadFile(filename)
	if nil != err {
		return err
	}
	//yaml.Unmarshal(data, &loaded)
	yaml.Unmarshal(data, &config_map)

	var md mapstructure.Metadata
	decoder_config := &mapstructure.DecoderConfig{
		Metadata: &md,
		Result:   &loaded,
	}

	decoder, err := mapstructure.NewDecoder(decoder_config)
	if err != nil {
		panic(err)
	}

	if err := decoder.Decode(config_map); err != nil {
		panic(err)
	}

	// Loop over the unused keys, add them to extra config
	if len(md.Unused) > 0 {
		if nil == config.AdditionalConfig {
			config.AdditionalConfig = make(map[string]string)
		}

		for _, key := range md.Unused {
			fmt.Printf("Key is %v\n", key)
			config.AdditionalConfig[key] = config_map[key]
		}
	}

	// Check the config values to see if any are already overridden
	// for each value, if it's unset, copy the config file's value (if present)
	if config.oneCRLEnvString == DEFAULT_ONECRLENV && loaded.oneCRLEnvString != "" {
		config.oneCRLEnvString = loaded.oneCRLEnvString
	}

	if config.oneCRLBucketString == DEFAULT_ONECRLBUCKET && loaded.oneCRLBucketString != "" {
		config.oneCRLBucketString = loaded.oneCRLBucketString
	}

	fmt.Printf("loaded bugzilla base is %s\n", loaded.BugzillaBase)
	if config.BugzillaBase == PREFIX_BUGZILLA_PROD && loaded.BugzillaBase != "" {
		fmt.Printf("overriding with loaded bugzilla base\n")
		config.BugzillaBase = loaded.BugzillaBase
		fmt.Printf("overridden bugzilla base is %s\n", config.BugzillaBase)
	}
	if config.BugzillaAPIKey == DEFAULT_DEFAULT {
		// if it's set in config, use that value
		if loaded.BugzillaAPIKey != "" {
			config.BugzillaAPIKey = loaded.BugzillaAPIKey
		} else {
			// attempt to get a value from environment
			config.BugzillaAPIKey = os.Getenv("bzapikey")
		}
	}
	if config.BugzillaReviewers == DEFAULT_DEFAULT && loaded.BugzillaReviewers != "" {
		config.BugzillaReviewers = loaded.BugzillaReviewers
	}
	if config.BugzillaBlockee == DEFAULT_DEFAULT && loaded.BugzillaBlockee != "" {
		config.BugzillaBlockee = loaded.BugzillaBlockee
	}
	if config.BugDescription == DEFAULT_DESCRIPTION && loaded.BugDescription != "" {
		config.BugDescription = loaded.BugDescription
	}
	if config.KintoUser == DEFAULT_DEFAULT {
		// if it's set in config, use that value
		if loaded.KintoUser != "" {
			config.KintoUser = loaded.KintoUser
		} else {
			// attempt to get a value from environment
			config.KintoUser = os.Getenv("kintouser")
		}
	}
	if config.Preview == DEFAULT_PREVIEW && loaded.Preview != "" {
		config.Preview = loaded.Preview
	}
	if config.EnforceCRLChecks == DEFAULT_ENFORCE_CRL_CHECKS && loaded.EnforceCRLChecks != "" {
		config.EnforceCRLChecks = loaded.EnforceCRLChecks
	}
	if config.KintoPassword == DEFAULT_DEFAULT {
		// if it's set in config, use that value
		if loaded.KintoPassword != "" {
			config.KintoPassword = loaded.KintoPassword
		} else {
			// attempt to get a value from environment
			config.KintoPassword = os.Getenv("kintopass")
		}
	}
	if config.KintoCollectionURL == DEFAULT_COLLECTION_URL && loaded.KintoCollectionURL != "" {
		config.KintoCollectionURL = loaded.KintoCollectionURL
	}

	if len(config.KintoUser) > 0 && len(config.KintoPassword) == 0 {
		fmt.Printf("Please enter the password for user %s\n", config.KintoUser)
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if nil != err {
			panic(err)
		}
		config.KintoPassword = string(bytePassword)
	}

	return nil
}

var conf = OneCRLConfig{}

func GetConfig() *OneCRLConfig {
	conf.loadConfig()
	return &conf
}

func DefineFlags() {
	flag.StringVar(&conf.oneCRLConfig, "onecrlconfig", DEFAULT_ONECRLCONFIG, "The OneCRL config file")
	flag.StringVar(&conf.oneCRLEnvString, "onecrlenv", DEFAULT_ONECRLENV, "The OneCRL Environment to use by default - values other than 'stage' will result in the production instance being used")
	flag.StringVar(&conf.oneCRLBucketString, "onecrlbucket", DEFAULT_ONECRLBUCKET, "The OneCRL bucket to use for reads")
	flag.StringVar(&conf.OneCRLVerbose, "onecrlverbose", DEFAULT_ONECRLVERBOSE, "Be verbose about OneCRL stuff")
	flag.StringVar(&conf.BugzillaBase, "bugzilla", PREFIX_BUGZILLA_PROD, "The bugzilla instance to use by default")
	flag.StringVar(&conf.BugzillaAPIKey, "bzapikey", DEFAULT_DEFAULT, "The bugzilla API key")
	flag.StringVar(&conf.BugzillaReviewers, "reviewers", DEFAULT_DEFAULT, "The reviewers for the buzilla attachmenets")
	flag.StringVar(&conf.BugzillaBlockee, "blockee", DEFAULT_DEFAULT, "What bugzilla bug should this bug block")
	flag.StringVar(&conf.BugDescription, "bugdescription", DEFAULT_DESCRIPTION, "The bugzilla comment to put in the bug")
	flag.StringVar(&conf.Preview, "preview", DEFAULT_PREVIEW, "Preview (don't write changes)")
	flag.StringVar(&conf.EnforceCRLChecks, "enforcecrlchecks", DEFAULT_ENFORCE_CRL_CHECKS, "Enforce CRL checks (options: yes, no)")
	flag.StringVar(&conf.KintoUser, "kintouser", DEFAULT_DEFAULT, "The kinto user")
	flag.StringVar(&conf.KintoPassword, "kintopass", DEFAULT_DEFAULT, "The kinto user's pasword")
	flag.StringVar(&conf.KintoCollectionURL, "collectionurl", DEFAULT_COLLECTION_URL, "The kinto collection URL")
}
