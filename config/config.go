package config

import (
	"errors"
	"flag"
	"fmt"
	"syscall"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"golang.org/x/crypto/ssh/terminal"
)

const ProductionPrefix string = "https://firefox.settings.services.mozilla.com"
const StagePrefix string = "https://settings.stage.mozaws.net"
const RecordsPathPrefix string = "/v1/buckets/"
const RecordsPathSuffix string = "/collections/certificates/records"

const PREFIX_BUGZILLA_PROD string = "https://bugzilla.mozilla.org"
const PREFIX_BUGZILLA_STAGE string = "https://bugzilla.allizom.org"

type OneCRLConfig struct {
	oneCRLConfig		string
	oneCRLEnvString		string `yaml:"onecrlenv"`
	oneCRLBucketString	string `yaml:"onecrlbucket"`
	OneCRLVerbose		string `yaml:"onecrlverbose"`
	BugzillaBase		string `yaml:"bugzilla"`
	BugzillaAPIKey		string `yaml:"bzapikey"`
	BugzillaReviewers	string `yaml:"reviewers"`
	BugzillaBlockee		string `yaml:"blockee"`
	BugDescription		string `yaml:"bugdescription"`
	Preview				string `yaml:"preview"`
	KintoUser			string `yaml:"kintouser"`
	KintoPassword		string `yaml:"kintopass"`
	KintoCollectionURL	string `yaml:"collectionurl"`
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
const DEFAULT_DESCRIPTION string = "Here are some entries: Please ensure that the entries are correct."


func (config *OneCRLConfig) loadConfig() error {
	// TODO: load the config from configuration file
	loaded :=  OneCRLConfig{}

	filename := config.oneCRLConfig
	if len(filename) == 0 {
		filename = DEFAULT_ONECRLCONFIG
	}
	data, err := ioutil.ReadFile(filename)
	if nil != err {
		return err
	}
	yaml.Unmarshal(data, &loaded)
	fmt.Printf("The unmarshalled config is %v\n", loaded)

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
	if config.BugzillaAPIKey == DEFAULT_DEFAULT && loaded.BugzillaAPIKey != "" {
		config.BugzillaAPIKey = loaded.BugzillaAPIKey
	}
	if config.BugzillaReviewers == DEFAULT_DEFAULT && loaded.BugzillaReviewers != "" {
		config.BugzillaReviewers = loaded.BugzillaReviewers
	}
	if config.BugzillaBlockee == DEFAULT_DEFAULT && loaded.BugzillaBlockee != "" {
		config.BugzillaBlockee = loaded.BugzillaBlockee
	}
	if config.BugDescription == DEFAULT_DESCRIPTION && loaded.BugDescription!= "" {
		config.BugDescription= loaded.BugDescription
	}
	if config.KintoUser == DEFAULT_DEFAULT && loaded.KintoUser!= "" {
		config.KintoUser = loaded.KintoUser
	}
	if config.Preview == DEFAULT_PREVIEW && loaded.Preview != "" {
		config.Preview = loaded.Preview
	}
	if config.KintoPassword == DEFAULT_DEFAULT && loaded.KintoPassword!= "" {
		config.KintoPassword = loaded.KintoPassword
	}
	if config.KintoCollectionURL == DEFAULT_COLLECTION_URL && loaded.KintoCollectionURL!= "" {
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

var conf = OneCRLConfig {}

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
	flag.StringVar(&conf.KintoUser, "kintouser", DEFAULT_DEFAULT, "The kinto user")
	flag.StringVar(&conf.KintoPassword, "kintopass", DEFAULT_DEFAULT, "The kinto user's pasword")
	flag.StringVar(&conf.KintoCollectionURL, "collectionurl", DEFAULT_COLLECTION_URL, "The kinto collection URL")
}
