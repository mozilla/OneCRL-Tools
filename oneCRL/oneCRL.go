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
	"net/http"
	"log"
	"os"
	"io/ioutil"
	"strings"
)

const ProductionPrefix string = "https://firefox.settings.services.mozilla.com"
const StagePrefix string = "https://settings.stage.mozaws.net"
const RecordsPath string = "/v1/buckets/blocklists/collections/certificates/records"

type Environment int

const (
	Production Environment = iota
	Stage
)

type OneCRLConfig struct {
	Environment Environment
}

func (config OneCRLConfig) GetRecordURL() string {

	var prefix string
	if config.Environment == Stage {
		prefix = StagePrefix
	} else {
		prefix = ProductionPrefix
	}
	return prefix + RecordsPath
}

type Record struct {
	IssuerName   string
	SerialNumber string
	Subject	     string
	PubKeyHash	 string
	Details struct {
		Who string
		Created string
		Bug string
		Name string
		Why string
	}
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

	fmt.Printf("Got URL data\n")

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
