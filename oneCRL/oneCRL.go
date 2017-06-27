package oneCRL

import (
	"bufio"
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"flag"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
	"golang.org/x/crypto/ssh/terminal"
)

const ProductionPrefix string = "https://firefox.settings.services.mozilla.com"
const StagePrefix string = "https://settings.stage.mozaws.net"
const RecordsPathPrefix string = "/v1/buckets/"
const RecordsPathSuffix string = "/collections/certificates/records"

const PREFIX_BUGZILLA_PROD string = "https://bugzilla.mozilla.org"
const PREFIX_BUGZILLA_STAGE string = "https://bugzilla.allizom.org"

const IssuerPrefix string = "issuer: "
const SerialPrefix string = "serial: "

// TODO: this looks unecessary - maybe remove
type OneCRLUpdate struct {
	Data Record `json:"data"`
}

type OneCRLConfig struct {
	oneCRLConfig		string
	oneCRLEnvString		string `yaml:"onecrlenv"`
	oneCRLBucketString	string `yaml:"onecrlbucket"`
	OneCRLVerbose		string `yaml:"onecrlverbose"`
	BugzillaBase		string `yaml:"bugzilla"`
	BugzillaAPIKey		string `yaml:"bzapikey"`
	BugzillaReviewers	string `yaml:"reviewers"`
	BugDescription		string `yaml:"bugdescription"`
	Preview				string `yaml:"preview"`
	KintoUser			string `yaml:"kintouser"`
	KintoPassword		string `yaml:"kintopass"`
	KintoCollectionURL	string `yaml:"collectionurl"`

}

func (config OneCRLConfig) GetRecordURL() string {
	var RecordsPath string = RecordsPathPrefix + config.oneCRLBucketString + RecordsPathSuffix

	if config.oneCRLEnvString == "stage" {
		return StagePrefix + RecordsPath
	}
	if config.oneCRLEnvString == "production" {
		return ProductionPrefix + RecordsPath
	}
	panic("valid onecrlenv values are \"stage\" and \"production\"")
}

const DEFAULT_ONECRLCONFIG string = ".config.yml"
const DEFAULT_ONECRLENV string = "production"
const DEFAULT_ONECRLBUCKET string = "blocklists"
const DEFAULT_ONECRLVERBOSE string = "no"
const DEFAULT_COLLECTION_URL string = "https://kinto-writer.stage.mozaws.net/v1/buckets/staging/collections/certificates"
const DEFAULT_DEFAULT string = ""
const DEFAULT_PREVIEW string = "no"
const DEFAULT_DESCRIPTION string = "Here are some entries: Please ensure that the entries are correct."

var conf = OneCRLConfig {}

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
	flag.StringVar(&conf.BugDescription, "bugdescription", DEFAULT_DESCRIPTION, "The bugzilla comment to put in the bug")
	flag.StringVar(&conf.Preview, "preview", DEFAULT_PREVIEW, "Preview (don't write changes)")
	flag.StringVar(&conf.KintoUser, "kintouser", DEFAULT_DEFAULT, "The kinto user")
	flag.StringVar(&conf.KintoPassword, "kintopass", DEFAULT_DEFAULT, "The kinto user's pasword")
	flag.StringVar(&conf.KintoCollectionURL, "collectionurl", DEFAULT_COLLECTION_URL, "The kinto collection URL")
}

type AttachmentFlag struct {
	Name string      `json:"name"`
	Status string    `json:"status"`
	Requestee string `json:"requestee"`
	New bool         `json:"new"`
}

type Attachment struct {
	ApiKey      string           `json:"api_key"`
	Ids         []int            `json:"ids"`
	ContentType string           `json:"content_type"`
	Data        string           `json:"data"`
	Summary     string           `json:"summary"`
	FileName    string           `json:"file_name"`
	Flags       []AttachmentFlag `json:"flags"`
	BugId       int              `json:"bug_id"`
	Comment     string           `json:"comment"`
}

type AttachmentResponse struct {
	Ids []string `json:"ids"`
}

type Bug struct {
	ApiKey      string `json:"api_key"`
	Product     string `json:"product"`
	Component   string `json:"component"`
	Version     string `json:"version"`
	Summary     string `json:"summary"`
	Comment     string `json:"comment"`
	Description string `json:"description"`
}

type BugResponse struct {
	Id int `json:"id"`
}

type Record struct {
	IssuerName   string `json:"issuerName"`
	SerialNumber string `json:"serialNumber"`
	Subject      string `json:"subject,omitempty"`
	PubKeyHash   string `json:"pubKeyHash,omitempty"`
	Enabled      bool   `json:"enabled"`
	Details struct {
		Who     string `json:"who"`
		Created string `json:"created"`
		Bug     string `json:"bug"`
		Name    string `json:"name"`
		Why     string `json:"why"`
	} `json:"details"`
}

func (record Record) EqualsRecord(otherRecord Record) bool {
	return record.IssuerName == otherRecord.IssuerName &&
		record.SerialNumber == otherRecord.SerialNumber &&
		record.Subject == otherRecord.Subject &&
		record.PubKeyHash == otherRecord.PubKeyHash
}

type Records struct {
	Data []Record
}

func StringFromRecord(record Record) string {
	if "" != record.Subject {
		return stringFromSubjectPubKeyHash(record.Subject, record.PubKeyHash)
	}
	return StringFromIssuerSerial(record.IssuerName, record.SerialNumber)
}

func stringFromSubjectPubKeyHash(subject string, pubKeyHash string) string {
	return fmt.Sprintf("subject: %s pubKeyHash: %s", subject, pubKeyHash)
}

func StringFromIssuerSerial(issuer string, serial string) string {
	return fmt.Sprintf("issuer: %s serial: %s", issuer, serial)
}


func getDataFromURL(url string, user string, pass string) ([]byte, error) {

	req, err := http.NewRequest("GET", url, nil)
	if len(user) > 0 {
		req.SetBasicAuth(user, pass)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if nil != err {
		return nil, err
	}

	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func FetchExistingRevocations(url string) ([]string, error) {
	if len(url) == 0 {
		return nil, errors.New("No URL was specified")
	}

	if "yes" == conf.OneCRLVerbose {
		fmt.Printf("Got URL data\n")
	}

	var existing []string

	user, pass := conf.KintoUser, conf.KintoPassword

	res := new(Records)
	data, err := getDataFromURL(url, user, pass)
	if nil != err {
		return nil, errors.New(fmt.Sprintf("problem loading existing data from URL %s", err))
	}

	err = json.Unmarshal(data, res)
	if nil != err {
		return nil, err
	}

	existing = make([]string, len(res.Data))
	for idx := range res.Data {
		existing[idx] = StringFromRecord(res.Data[idx])
	}

	return existing, nil
}

func ByteArrayEquals(a []byte, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i, v := range a {
        if v != b[i] {
            return false
        }
    }
    return true
}

func DNToRFC4514(name string) (string, error) {
	rawDN, _ := base64.StdEncoding.DecodeString(name)
	rdns := new(pkix.RDNSequence)
	_, err := asn1.Unmarshal(rawDN, rdns)
	
	return RFC4514ish(*rdns), err
}

func hexify(arr []byte, separate bool, upperCase bool) string {
	var encoded bytes.Buffer
	for i := 0; i < len(arr); i++ {
		encoded.WriteString(strings.ToUpper(hex.EncodeToString(arr[i : i+1])))
		if i < len(arr)-1 && separate {
			encoded.WriteString(":")
		}
	}
	retval := encoded.String()
	if !upperCase {
		retval = strings.ToLower(retval)
	}
	return retval
}

func SerialToString(encoded string, separate bool, upper bool) (string, error) {
	rawSerial, err := base64.StdEncoding.DecodeString(encoded)
	return hexify(rawSerial, separate, upper), err
}

func NamesDataMatches(name1 []byte, name2 []byte) bool {
	// Go's asn.1 marshalling support does not maintain original encodings.
	// Because if this, if the data are the same other than the encodings then
	// although bytewise comparisons on the original data failed, we can assume
	// that encoding differences will go away when we marshal back from
	// pkix.RDNSequence back to actual asn.1 data.

	// ensure our names decode to pkix.RDNSequences
	rdns1 := new(pkix.RDNSequence)
	_, errUnmarshal1 := asn1.Unmarshal(name1, rdns1)
	if nil != errUnmarshal1 {
		return false
	}

	rdns2 := new(pkix.RDNSequence)
	_, errUnmarshal2 := asn1.Unmarshal(name2, rdns2)
	if nil != errUnmarshal2 {
		return false
	}

	marshalled1, marshall1err := asn1.Marshal(*rdns1)
	if nil != marshall1err {
		return false
	}
	marshalled2, marshall2err := asn1.Marshal(*rdns2)
	if nil != marshall2err {
		return false
	}

	return ByteArrayEquals(marshalled1, marshalled2)
}

func RFC4514ish(rdns pkix.RDNSequence) string {
	retval := ""
	for _, rdn := range rdns {
		if len(rdn) == 0 {
			continue
		}
		atv := rdn[0]
		value, ok := atv.Value.(string)
		if !ok {
			continue
		}
		t := atv.Type
		tStr := ""
		if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
			switch t[3] {
			case 3:
				tStr = "CN"
			case 7:
				tStr = "L"
			case 8:
				tStr = "ST"
			case 10:
				tStr = "O"
			case 11:
				tStr = "OU"
			case 6:
				tStr = "C"
			case 9:
				tStr = "STREET"
			}
		}
		if len(t) == 7 &&
			t[0] == 1 &&
			t[1] == 2 &&
			t[2] == 840 &&
			t[3] == 113549 &&
			t[4] == 1 &&
			t[5] == 9 &&
			t[6] == 1 {
				tStr = "emailAddress"
			}

		sep := ""
		if len(retval) > 0 {
			sep = ", "
		}

		// quote values that contain a comma
		if strings.Contains(value, ",") {
			value = "\"\"" + value + "\"\""
		}
		retval = retval + sep + tStr + "=" + value
	}
	return retval
}

type OneCRLLoader interface {
	LoadRecord(record Record)
}

// TODO: fix loading functions to get data from a reader

func LoadJSONFromURL(url string, loader OneCRLLoader) error {
	var err error
	res := new(Records)
	r, err := http.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(res)
	if nil != err {
		return err
	}

	for idx := range res.Data {
		loader.LoadRecord(res.Data[idx])
	}

	return nil
}

func LoadRevocationsTxtFromFile(filename string, loader OneCRLLoader) error {
	var (
		err error
	)
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var dn = ""
	for scanner.Scan() {
		// process line
		line := scanner.Text()
		// Ignore comments
		if 0 == strings.Index(line, "#") {
			continue
		}
		if 0 == strings.Index(line, " ") {
			if len(dn) == 0 {
				log.Fatal("A serial number with no issuer is not valid. Exiting.")
			}
			record := Record{IssuerName:dn, SerialNumber:strings.Trim(line," ")}
			loader.LoadRecord(record)
			continue
		}
		if 0 == strings.Index(line, "\t") {
			log.Fatal("revocations.txt containing subject / pubkey pairs not yet supported")
			log.Fatal("A public key hash with no subject is not valid. Exiting.")
		}
		dn = line
	}
	
	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return nil
}

func LoadRevocationsFromBug(filename string, loader OneCRLLoader) error {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// process line
		line := scanner.Text()

		// parse the issuer and serial lines from the bug data
		issuerIndex := strings.Index(line, IssuerPrefix)
		serialIndex := strings.Index(line, SerialPrefix)

		issuer := line[issuerIndex + len(IssuerPrefix): serialIndex - 1]
		serial := line[serialIndex + len(SerialPrefix): len(line)]

		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("Loading revocation. issuer: \"%s\", serial: \"%s\"\n", issuer, serial)
		}

		record := Record{IssuerName:issuer, SerialNumber:serial}
		loader.LoadRecord(record)
	}

	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return nil
}

func CreateBug(bug Bug) (int, error) {
	// POST the bug
	bugNum := -1;
	url := conf.BugzillaBase + "/rest/bug"
	marshalled, err := json.Marshal(bug)
	if "yes" == conf.OneCRLVerbose {
		fmt.Printf("POSTing %s to %s\n", marshalled, url);
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(marshalled))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return bugNum, err
	}
	if "yes" == conf.OneCRLVerbose {
		fmt.Printf("status code is %d\n", resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)
		var response BugResponse
		err = dec.Decode(&response)
		if err != nil {
			return bugNum, err
		} else {
			bugNum = response.Id

			if "yes" == conf.OneCRLVerbose {
				fmt.Printf("%v\n", response.Id)
			}
		}
	defer resp.Body.Close()

	return bugNum, nil
}

func AttachToBug(bugNum int, apiKey string, attachments []Attachment) (error) {
	// loop over the attachments, add each to the bug
	for _, attachment := range attachments {
		attUrl := fmt.Sprintf(conf.BugzillaBase + "/rest/bug/%d/attachment", bugNum)
		attachment.Ids = []int {bugNum}
		attachment.ApiKey = apiKey
		// TODO: Don't set these if they're already set
		attachment.FileName = "BugData.txt"
		attachment.Summary = "Intermediates to be revoked"
		attachment.ContentType = "text/plain"
		attachment.Comment = "Revocation data for new records"
		attachment.BugId = bugNum
		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("Attempting to marshal %v\n", attachment)
		}
		attMarshalled, err := json.Marshal(attachment)
		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("POSTing %s to %s\n", attMarshalled, attUrl)
		}
		attReq, err := http.NewRequest("POST", attUrl, bytes.NewBuffer(attMarshalled))
		attReq.Header.Set("Content-Type", "application/json")
		attClient := &http.Client{}
		attResp, err := attClient.Do(attReq)
		if err != nil {
			return err
		}
		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("att response %s\n", attResp);
		}
	}
	return nil
}

func AddEntries(records *Records, createBug bool) error {
	issuerMap := make(map[string][]string)

	attachment := ""

	bugNum := -1

	now := time.Now()
	nowString := now.Format("2006-01-02T15:04:05Z")

	if (conf.Preview != "yes") {
		bug := Bug{}
		bug.ApiKey = conf.BugzillaAPIKey
		bug.Product = "Toolkit"
		bug.Component = "Blocklisting"
		bug.Version = "unspecified"
		bug.Summary = fmt.Sprintf("CCADB entries generated %s", nowString)
		bug.Description = conf.BugDescription

		var err error
		bugNum, err = CreateBug(bug)
		if err != nil {
			panic(err)
		}
	}

	for _, record := range records.Data {
		// TODO: We don't need to build an issuer map if we're not outputting
		// entries directly. If we *do* need to do this, the functionality for
		// making revocations.txt style data should live in oneCRL.go
		if issuers, ok := issuerMap[record.IssuerName]; ok {
			issuerMap[record.IssuerName] = append(issuers, record.SerialNumber)
		} else {
			issuerMap[record.IssuerName] = []string{record.SerialNumber}
		}

		if record.Details.Bug == "" {
			record.Details.Bug = fmt.Sprintf("%s/show_bug.cgi?id=%d",conf.BugzillaBase, bugNum)
		}
		if record.Details.Created == "" {
			record.Details.Created = nowString
		}
		
		update := new(OneCRLUpdate)
		update.Data = record
		marshalled, _ := json.Marshal(update)

		// Upload the created entry to Kinto
		// TODO: Batch these, don't send single requests
		if conf.Preview != "yes" {
			if "yes" == conf.OneCRLVerbose {
				fmt.Printf("Will POST to \"%s\" with \"%s\"\n", conf.KintoCollectionURL + "/records", marshalled)
			}
			req, err := http.NewRequest("POST", conf.KintoCollectionURL + "/records", bytes.NewBuffer(marshalled))

			if len(conf.KintoUser) > 0 {
				req.SetBasicAuth(conf.KintoUser, conf.KintoPassword)
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)

			if "yes" == conf.OneCRLVerbose {
				fmt.Printf("status code is %d\n", resp.StatusCode)
				fmt.Printf("record data is %s\n", StringFromRecord(record))
			}
			attachment = attachment + StringFromRecord(record) + "\n"
			defer resp.Body.Close()

			if err != nil {
				panic(err)
			}
		} else {
			fmt.Printf("Would POST to \"%s\" with \"%s\"\n", conf.KintoCollectionURL + "/records", marshalled)
		}
	}

	// TODO: request review on the Kinto change
	if conf.Preview != "yes" {
		// TODO: Factor out the request stuff...
		reviewJSON := "{\"data\": {\"status\": \"to-review\"}}"

		// PATCH the object to set the status to to-review
		req, err := http.NewRequest("PATCH", conf.KintoCollectionURL, bytes.NewBuffer([]byte(reviewJSON)))

		if len(conf.KintoUser) > 0 {
			req.SetBasicAuth(conf.KintoUser, conf.KintoPassword)
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)

		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("requested review - status code is %d\n", resp.StatusCode)
		}

		defer resp.Body.Close()

		if err != nil {
			panic(err)
		}

	}

	// upload the created entries to bugzilla
	if conf.Preview != "yes" {
		attachments := make([]Attachment, 1)
		data := []byte(attachment)
		str := base64.StdEncoding.EncodeToString(data)
		attachments[0] = Attachment{}
		attachments[0].ApiKey = conf.BugzillaAPIKey
		attachments[0].Data = str


		attachments[0].Flags = make([]AttachmentFlag,0,1)
		// create flags for the reviewers
		for _, reviewer := range strings.Split(conf.BugzillaReviewers, ",") {
			trimmedReviewer := strings.Trim(reviewer," ")
			if len(trimmedReviewer) > 0 {
				flag := AttachmentFlag{}
				flag.Name = "review"
				flag.Status = "?"
				flag.Requestee = trimmedReviewer
				flag.New = true
				attachments[0].Flags = append(attachments[0].Flags, flag)
			}
		}

		err := AttachToBug(bugNum, conf.BugzillaAPIKey, attachments)
		if err != nil {
			fmt.Printf(str)
			panic(err)
		}
	}

	// TODO: put output into the bug
	return nil
}
