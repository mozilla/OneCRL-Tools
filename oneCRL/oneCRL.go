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
)

const ProductionPrefix string = "https://firefox.settings.services.mozilla.com"
const StagePrefix string = "https://settings.stage.mozaws.net"
const RecordsPath string = "/v1/buckets/blocklists/collections/certificates/records"

const PREFIX_BUGZILLA_PROD string = "https://bugzilla.mozilla.org"
const PREFIX_BUGZILLA_STAGE string = "https://bugzilla.allizom.org"

const KintoWriterURL string = "https://kinto-writer.stage.mozaws.net/v1/buckets/staging/collections/certificates/records"

const IssuerPrefix string = "issuer: "
const SerialPrefix string = "serial: "

type OneCRLEnvironment int
const (
	Production OneCRLEnvironment = iota
	Stage
)

type OneCRLConfig struct {
	oneCRLEnvString string `yaml:"onecrlenv"`
	OneCRLVerbose   string `yaml:"onecrlverbose"`
	BugzillaBase string    `yaml:"bugzilla"`
	BugzillaAPIKey string  `yaml:"bzapikey"`
	Preview string         `yaml:"preview"`
	KintoUser string       `yaml:"kintouser"`
	KintoPassword string   `yaml:"kintopass"`
	KintoUploadURL string  `yaml:"uploadurl"`

}

func (config OneCRLConfig) GetRecordURL() string {
	if config.oneCRLEnvString == "stage" {
		return StagePrefix + RecordsPath
	}
	if config.oneCRLEnvString == "production" {
		return ProductionPrefix + RecordsPath
	}
	panic("valid onecrlenv values are \"stage\" and \"production\"")
}

const DEFAULT_ONECRLENV string = "production"
const DEFAULT_ONECRLVERBOSE string = "no"
const DEFAULT_UPLOAD_URL string = "https://kinto-writer.stage.mozaws.net/v1/buckets/staging/collections/certificates/records"
const DEFAULT_DEFAULT string = ""

func (config *OneCRLConfig) LoadConfig() error {
	// TODO: load the config from configuration file
	loaded :=  OneCRLConfig{}

	data, err := ioutil.ReadFile(".config.yml")
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
	if config.BugzillaBase == PREFIX_BUGZILLA_PROD && loaded.BugzillaBase != "" {
		config.BugzillaBase = loaded.BugzillaBase
	}
	if config.BugzillaAPIKey == DEFAULT_DEFAULT && loaded.BugzillaAPIKey != "" {
		config.BugzillaAPIKey = loaded.BugzillaAPIKey
	}
	if config.KintoUser == DEFAULT_DEFAULT && loaded.KintoUser!= "" {
		config.KintoUser = loaded.KintoUser
	}
	if config.KintoPassword == DEFAULT_DEFAULT && loaded.KintoPassword!= "" {
		config.KintoPassword = loaded.KintoPassword
	}
	if config.KintoUploadURL == DEFAULT_UPLOAD_URL && loaded.KintoUploadURL!= "" {
		config.KintoUploadURL = loaded.KintoUploadURL
	}
	return nil
}

var Config = OneCRLConfig {}

func DefineFlags() {
	flag.StringVar(&Config.oneCRLEnvString, "onecrlenv", DEFAULT_ONECRLENV, "The OneCRL Environment to use by default - values other than 'stage' will result in the production instance being used")
	flag.StringVar(&Config.OneCRLVerbose, "onecrlverbose", DEFAULT_ONECRLVERBOSE, "Be verbose about OneCRL stuff")
	flag.StringVar(&Config.BugzillaBase, "bugzilla", PREFIX_BUGZILLA_PROD, "The bugzilla instance to use by default")
	flag.StringVar(&Config.BugzillaAPIKey, "bzapikey", DEFAULT_DEFAULT, "The bugzilla API key")
	flag.StringVar(&Config.KintoUser, "kintouser", DEFAULT_DEFAULT, "The kinto user")
	flag.StringVar(&Config.KintoPassword, "kintopass", DEFAULT_DEFAULT, "The kinto user's pasword")
	flag.StringVar(&Config.KintoUploadURL, "uploadurl", DEFAULT_UPLOAD_URL, "The kinto upload URL")
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


func getDataFromURL(url string) ([]byte, error) {
	r, _ := http.Get(url)
	defer r.Body.Close()

	return ioutil.ReadAll(r.Body)
}

func FetchExistingRevocations(url string) ([]string, error) {
	if len(url) == 0 {
		return nil, errors.New("No URL was specified")
	}

	if "yes" == Config.OneCRLVerbose {
		fmt.Printf("Got URL data\n")
	}

	var existing []string

	res := new(Records)
	data, err := getDataFromURL(url)
	if nil != err {
		return nil, errors.New(fmt.Sprintf("problem loading existing data from URL %s", err))
	}
	json.Unmarshal(data, res)
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

		if "yes" == Config.OneCRLVerbose {
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

func UploadRecords(records Records, createBug bool) error {
	return nil;
}

func CreateBug(bug Bug, attachments []Attachment) (error) {
	// POST the bug
	url := Config.BugzillaBase + "/rest/bug"
	marshalled, err := json.Marshal(bug)
	if "yes" == Config.OneCRLVerbose {
		fmt.Printf("POSTing %s to %s\n", marshalled, url);
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(marshalled))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	if "yes" == Config.OneCRLVerbose {
		fmt.Printf("status code is %d\n", resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)
		var response BugResponse
		err = dec.Decode(&response)
		if err != nil {
			panic(err)
		} else {
			if "yes" == Config.OneCRLVerbose {
				fmt.Printf("%v\n", response.Id);
			}
			// loop over the attachments, add each to the bug
			for _, attachment := range attachments {
				attUrl := fmt.Sprintf(Config.BugzillaBase + "/rest/bug/%d/attachment", response.Id)
				attachment.Ids = []int {response.Id}
				attachment.ApiKey = bug.ApiKey
				attachment.FileName = "BugData.txt"
				attachment.Summary = "Intermediates to be revoked"
				attachment.ContentType = "text/plain"
				attachment.Comment = "Revocation data for new records"
				attachment.Flags = make([]AttachmentFlag,0,1)
				attachment.BugId = response.Id
				if "yes" == Config.OneCRLVerbose {
					fmt.Printf("Attempting to marshal %v\n", attachment)
				}
				attMarshalled, err := json.Marshal(attachment)
				if "yes" == Config.OneCRLVerbose {
					fmt.Printf("POSTing %s to %s\n", attMarshalled, attUrl)
				}
				attReq, err := http.NewRequest("POST", attUrl, bytes.NewBuffer(attMarshalled))
	            attReq.Header.Set("Content-Type", "application/json")
				attClient := &http.Client{}
				attResp, err := attClient.Do(attReq)
				if err != nil {
					panic(err)
				}
				if "yes" == Config.OneCRLVerbose {
					fmt.Printf("att response %s\n", attResp);
				}
			}
		}
	defer resp.Body.Close()

	return nil
}
