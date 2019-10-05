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
const RecordsPathSuffix string = "/collections/onecrl/records"

const PREFIX_BUGZILLA_PROD string = "https://bugzilla.mozilla.org"
const PREFIX_BUGZILLA_STAGE string = "https://bugzilla.allizom.org"

const DEFAULT_BUG_PRODUCT string = "Toolkit"
const DEFAULT_BUG_COMPONENT string = "Blocklisting"
const DEFAULT_BUG_VERSION string = "unspecified"

type OneCRLConfig struct {
	oneCRLConfig       string
	oneCRLEnvString    string `mapstructure:"onecrlenv"`
	oneCRLBucketString string `mapstructure:"onecrlbucket"`
	OneCRLVerbose      string `mapstructure:"onecrlverbose"`
	BugzillaBase       string `mapstructure:"bugzilla"`
	BugzillaAPIKey     string `mapstructure:"bzapikey"`
	BugzillaReviewers  string `mapstructure:"reviewers"`
	BugProduct         string `mapstructure:"bugproduct"`
	BugComponent       string `mapstructure:"bugcomponent"`
	BugVersion         string `mapstructure:"bugversion"`
	BugzillaBlockee    string `mapstructure:"blockee"`
	BugDescription     string `mapstructure:"bugdescription"`
	Preview            string `mapstructure:"preview"`
	EnforceCRLChecks   string `mapstructure:"enforcecrlchecks"`
	KintoUser          string `mapstructure:"kintouser"`
	KintoPassword      string `mapstructure:"kintopass"`
	KintoToken         string `mapstructure:"kintotoken"`
	KintoCollectionURL string `mapstructure:"collectionurl"`
	SkipBugzilla       bool   // Must be set by CLI flags
	AdditionalConfig   map[string]string
}

// GetRecordURLForEnv returns the the URL (as a string) for a given OneCRL Environment ("stage" or "production")
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
const DEFAULT_ONECRLBUCKET string = "security-state"
const DEFAULT_ONECRLVERBOSE string = "no"
const DEFAULT_COLLECTION_URL string = "https://settings-writer.stage.mozaws.net/v1/buckets/ecurity-state-staging/collections/onecrl"
const DEFAULT_DEFAULT string = ""
const DEFAULT_PREVIEW string = "no"
const DEFAULT_ENFORCE_CRL_CHECKS string = "yes"
const DEFAULT_DESCRIPTION string = "Here are some entries: Please ensure that the entries are correct."

func (config *OneCRLConfig) loadConfig() error {
	// load the config from configuration file
	filename := config.oneCRLConfig
	fmt.Printf("config file was: %v\n", filename)
	if filename == DEFAULT_ONECRLCONFIG {
		envFilename := os.Getenv("onecrlconfig")
		fmt.Printf("Looking for config file in environment: %v\n", envFilename)
		if 0 != len(envFilename) {
			filename = envFilename
		}
	}
	if len(filename) == 0 {
		filename = DEFAULT_ONECRLCONFIG
	}
	data, err := ioutil.ReadFile(filename)
	if nil != err {
		return err
	}

	// Load the yaml into a map first - so we capture additional config options
	configMap := map[string]string{}
	yaml.Unmarshal(data, &configMap)

	// Transfer entries from the map that we recognise
	loaded := OneCRLConfig{}
	var md mapstructure.Metadata
	decoderConfig := &mapstructure.DecoderConfig{
		Metadata: &md,
		Result:   &loaded,
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		panic(err)
	}

	if err := decoder.Decode(configMap); err != nil {
		panic(err)
	}

	// Loop over the unused keys, add them to additional config
	if len(md.Unused) > 0 {
		if nil == config.AdditionalConfig {
			config.AdditionalConfig = make(map[string]string)
		}

		for _, key := range md.Unused {
			fmt.Printf("Key is %v\n", key)
			config.AdditionalConfig[key] = configMap[key]
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
	
	//Bug report settings
	if config.BugProduct == DEFAULT_BUG_PRODUCT && loaded.BugProduct != "" {
		config.BugProduct = loaded.BugProduct
	}
	if config.BugComponent == DEFAULT_BUG_COMPONENT && loaded.BugComponent != "" {
		config.BugComponent = loaded.BugComponent
	}
	if config.BugVersion == DEFAULT_BUG_VERSION && loaded.BugVersion != "" {
		config.BugVersion = loaded.BugVersion
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
	if config.KintoToken == DEFAULT_DEFAULT {
		// if it's set in config, use that value
		if loaded.KintoToken != "" {
			config.KintoToken = loaded.KintoToken
		} else {
			// attempt to get a value from environment
			config.KintoToken = os.Getenv("kintotoken")
		}
	}
	if config.KintoCollectionURL == DEFAULT_COLLECTION_URL && loaded.KintoCollectionURL != "" {
		config.KintoCollectionURL = loaded.KintoCollectionURL
	}

	if len(config.KintoToken) == 0 && len(config.KintoUser) > 0 && len(config.KintoPassword) == 0 {
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

// GetConfig obtains the system-wide default config including entries loaded from configuration and the environment.
func GetConfig() *OneCRLConfig {
	conf.loadConfig()
	return &conf
}

// DefineFlags defines the command line flags common to different OneCRL tools.
func DefineFlags() {
	flag.StringVar(&conf.oneCRLConfig, "onecrlconfig", DEFAULT_ONECRLCONFIG, "The OneCRL config file")
	flag.StringVar(&conf.oneCRLEnvString, "onecrlenv", DEFAULT_ONECRLENV, "The OneCRL Environment to use by default - values other than 'stage' will result in the production instance being used")
	flag.StringVar(&conf.oneCRLBucketString, "onecrlbucket", DEFAULT_ONECRLBUCKET, "The OneCRL bucket to use for reads")
	flag.StringVar(&conf.OneCRLVerbose, "onecrlverbose", DEFAULT_ONECRLVERBOSE, "Be verbose about OneCRL stuff")
	flag.StringVar(&conf.BugzillaBase, "bugzilla", PREFIX_BUGZILLA_PROD, "The bugzilla instance to use by default")
	flag.StringVar(&conf.BugzillaAPIKey, "bzapikey", DEFAULT_DEFAULT, "The bugzilla API key")
	flag.StringVar(&conf.BugProduct, "bugproduct", DEFAULT_BUG_PRODUCT, "The defualt product of the bug")
	flag.StringVar(&conf.BugComponent, "bugcomponent", DEFAULT_BUG_COMPONENT, "The defualt product component of the bug")
	flag.StringVar(&conf.BugVersion, "bugversion", DEFAULT_BUG_VERSION, "The defualt component version of the bug")
	flag.StringVar(&conf.BugzillaReviewers, "reviewers", DEFAULT_DEFAULT, "The reviewers for the buzilla attachmenets")
	flag.StringVar(&conf.BugzillaBlockee, "blockee", DEFAULT_DEFAULT, "What bugzilla bug should this bug block")
	flag.StringVar(&conf.BugDescription, "bugdescription", DEFAULT_DESCRIPTION, "The bugzilla comment to put in the bug")
	flag.StringVar(&conf.Preview, "preview", DEFAULT_PREVIEW, "Preview (don't write changes)")
	flag.StringVar(&conf.EnforceCRLChecks, "enforcecrlchecks", DEFAULT_ENFORCE_CRL_CHECKS, "Enforce CRL checks (options: yes, no)")
	flag.StringVar(&conf.KintoUser, "kintouser", DEFAULT_DEFAULT, "The kinto user")
	flag.StringVar(&conf.KintoPassword, "kintopass", DEFAULT_DEFAULT, "The kinto user's pasword")
	flag.StringVar(&conf.KintoCollectionURL, "collectionurl", DEFAULT_COLLECTION_URL, "The kinto collection URL")
	flag.BoolVar(&conf.SkipBugzilla, "skipbugzilla", false, "Skip updating Bugzilla")
}
