package observatory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

const (
	scheme              = "https:/"
	baseURL             = "tls-observatory.services.mozilla.com/api"
	apiVersion          = "v1"
	certificateEndpoint = "certificate"
)

var obsURL = strings.Join([]string{scheme, baseURL, apiVersion, certificateEndpoint}, "/")

// TimeFMT is the format of the time string
// used by the TLS Observatory.
const TimeFMT = "2006-01-02T15:04:05Z"

// Certificate is a the JSON deserialization of the resulting
// parse from the TLS Observatory's /certificate endpoing.
type Certificate struct {
	Raw                string
	CA                 bool      `json:"ca"`
	CiscoUmbrellaRank  int       `json:"ciscoUmbrellaRank"`
	FirstSeenTimestamp time.Time `json:"firstSeenTimestamp"`
	Hashes             struct {
		PinSHA256         string `json:"pin-sha256"`
		SHA1              string `json:"sha1"`
		SHA256            string `json:"sha256"`
		SHA256SubjectSPKI string `json:"spki-sha256"`
	} `json:"hashes"`
	ID                 int          `json:"id"`
	Issuer             Organization `json:"issuer"`
	Key                Key          `json:"key"`
	LastSeenTimestamp  time.Time    `json:"lastSeenTimestamp"`
	SerialNumber       string       `json:"serialNumber"`
	SignatureAlgorithm string       `json:"signatureAlgorithm"`
	Subject            Organization `json:"subject"`
	ValidationInfo     struct {
		Android   Validation
		Apple     Validation
		Microsoft Validation
		Mozilla   Validation
		Ubuntu    Validation
	} `json:"validationInfo"`
	Validity struct {
		NotAfter  time.Time `json:"notAfter"`
		NotBefore time.Time `json:"notBefore"`
	} `json:"validity"`
	Version                int    `json:"version"`
	X509v3BasicConstraints string `json:"x509v3BasicConstraints"`
	X509v3Extensions       struct {
		AuthorityKeyID           string   `json:"authorityKeyId"`
		CRLDistributionPoint     []string `json:"crlDistributionPoint"`
		IsTechnicallyConstrained bool     `json:"isTechnicallyConstrained"`
		ExtendedKeyUsage         []string `json:"extendedKeyUsage"`
		KeyUsage                 []string `json:"keyUsage"`
		PolicyIdentifiers        []string `json:"policyIdentifiers"`
		SubjectAlternativeName   []string `json:"subjectAlternativeName"`
		SubjectKeyID             string   `json:"subjectKeyId"`
	} `json:"x509v3Extensions"`
}

// Organization represents an issuer/subject object.
type Organization struct {
	C  []string `json:"c"`
	CN string   `json:"cn"`
	O  []string `json:"o"`
	OU []string `json:"ou"`
}

// Validation represents all objects whose sole
// purpose is to convey validity.
type Validation struct {
	IsValid bool `json:"isValid"`
}

// Key represents a public key of either RSA or ECC.
// If the key is RSA, then `curve` will be the empty string.
// If the key is ECC, then `exponent` will be zero.
type Key struct {
	Alg      string `json:"alg"`
	Exponent int    `json:"exponent"`
	Curve    string `json:"curve"`
	Size     int    `json:"size"`
}

// ParseFromObservatory submits the given DER Encoded PEM
// to the TLS Observatory /certificate endpoint for parsing
// and returns the result.
func ParseFromObservatory(pem string) (*Certificate, error) {
	b, c, err := createFormFile(pem, "certificate")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", obsURL, b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", c)
	req.Header.Add("X-Automated-Tool", `https://github.com/mozilla/OneCRL-Tools observatory"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// Overrides above error? Likely network error and could be cause
			// of the original error.
			return nil, err
		}
		return nil, fmt.Errorf("error parsing PEM: %v\ngot body: %v", pem, string(body))
	}
	cert := new(Certificate)
	err = json.NewDecoder(resp.Body).Decode(cert)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func createFormFile(pem, name string) (io.Reader, string, error) {
	b := bytes.Buffer{}
	form := multipart.NewWriter(&b)
	pemField, err := form.CreateFormFile(name, name)
	if err != nil {
		return nil, "", err
	}
	_, err = pemField.Write([]byte(pem))
	if err != nil {
		return nil, "", err
	}
	// Must close before returning (not defer) in order for the terminal sequence
	// to be written. Otherwise we will get an unexpected EOF.
	form.Close()
	return bytes.NewReader(b.Bytes()), form.FormDataContentType(), nil
}
