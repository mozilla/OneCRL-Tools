package obsDiffCCADB

// observatoryMappings.go contains functions and definitions for
// normalizing data returned by the TLS Observatory into a format
// appropriate for the CCADB's schema.
//
// Examples include converting a slice into a CSV string, or
// constructing a string describing the public key algorithm
// from a struct.

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mozilla/OneCRL-Tools/ccadb"
	"github.com/mozilla/OneCRL-Tools/observatory"
)

const (
	comma        = `.*,.*`
	plus         = `.*\+.*`
	equals       = `.*=.*`
	doubleQuote  = `.*".*`
	openChevron  = `.*<.*`
	closeChevron = `.*>.*`
	hash         = `.*#.*`
	semiColon    = `.*;.*`

	backslash = `.*\\.*`

	leadingSpace      = `^\s+.*`
	trailingSpace     = `.*\s+$`
	consecutiveSpaces = `.*\s{2,}.*`

	// AllowLDAPCRLs determines whether or not to allow LDAP CR endpoints
	// into the CRL. Defaults to false.
	AllowLDAPCRLs = false
)

var specialChars = []string{comma,
	plus,
	equals,
	doubleQuote,
	openChevron,
	closeChevron,
	hash,
	semiColon,
	backslash,
	leadingSpace,
	trailingSpace,
	consecutiveSpaces}

// (.*,.*|.*\+.*|.*=.*|.*".*|.*<.*|.*>.*|.*#.*|.*;.*|^\s+.*|.*\s+$|.*\s{2,}.*)
var dnEscapeRegex = regexp.MustCompile(fmt.Sprintf("(%v)", strings.Join(specialChars, "|")))

// FmtDN formats the provide Organization struct into a single
// distinguished name string using the format "CN=%v, OU=%v, O=%v, C=%v".
// The distinguished name is constructed using the rules found at RFC1779
// (https://tools.ietf.org/html/rfc1779). Double quotes are used as the escape mechanism,
// except in the case of double quotes themselves, which are escaped using a `\`.
// Refer to the following BNF outlined in section 2.3.
//
//    <name> ::= <name-component> ( <spaced-separator> )
//           | <name-component> <spaced-separator> <name>
//
//    <spaced-separator> ::= <optional-space>
//                    <separator>
//                    <optional-space>
//
//    <separator> ::=  "," | ";"
//
//    <optional-space> ::= ( <CR> ) *( " " )
//
//    <name-component> ::= <attribute>
//            | <attribute> <optional-space> "+"
//              <optional-space> <name-component>
//
//    <attribute> ::= <string>
//            | <key> <optional-space> "=" <optional-space> <string>
//
//    <key> ::= 1*( <keychar> ) | "OID." <oid> | "oid." <oid>
//    <keychar> ::= letters, numbers, and space
//
//    <oid> ::= <digitstring> | <digitstring> "." <oid>
//    <digitstring> ::= 1*<digit>
//    <digit> ::= digits 0-9
//
//    <string> ::= *( <stringchar> | <pair> )
//             | '"' *( <stringchar> | <special> | <pair> ) '"'
//             | "#" <hex>
//
//
//    <special> ::= "," | "=" | <CR> | "+" | "<" |  ">"
//             | "#" | ";"
//
//    <pair> ::= "\" ( <special> | "\" | '"')
//    <stringchar> ::= any character except <special> or "\" or '"'
//
//
//    <hex> ::= 2*<hexchar>
//    <hexchar> ::= 0-9, a-f, A-F
func FmtDN(o observatory.Organization) string {
	return fmt.Sprintf("CN=%v, OU=%v, O=%v, C=%v",
		FmtRDN(o.CN), FmtMultivaluedRDN(o.OU), FmtMultivaluedRDN(o.O), FmtMultivaluedRDN(o.C))
}

// FmtRDN performs any necessary escaping of the provided
// string in order to make it a valid RDN field.
//
// It returns the STRING "null" (not the null singleton)
// if the provided string is empty.
func FmtRDN(rdn string) string {
	if len(rdn) == 0 {
		// There is nothing in the RFC about empty fields, however
		// the CCADB is currently filling these voids in with null.
		return "null"
	}
	if dnEscapeRegex.MatchString(rdn) {
		// We use the double quote method to espace and entire field.
		// This is both easier to code as well as being easier on the eyes.
		// However, this also means that if there are any double quotes in the text
		// that they must be escaped with a `\` before enclosing the entire string in
		// double quotes.
		return fmt.Sprintf(`"%v"`, strings.Replace(rdn, `"`, `\"`, -1))
	}
	return rdn
}

// FmtMultivaluedRDN performs any necessary escaping and concatenation
// of the provided string in order to make it a valid RDN field.
//
// It returns the STRING "null" (not the null singleton)
// if the provided string is empty.
func FmtMultivaluedRDN(rdn []string) string {
	if len(rdn) == 0 {
		// There is nothing in the RFC about empty fields, however
		// the CCADB is currently filling these voids in with null.
		return "null"
	}
	fmted := make([]string, len(rdn))
	for i, v := range rdn {
		fmted[i] = FmtRDN(v)
	}
	return strings.Join(fmted, "+")
}

// SliceToCSV constructs a CSV string from the provided string slice.
func SliceToCSV(s []string) string {
	// Create a copy since we're sorting. Don't know if this is worth
	// doing in the current context, but it avoids surprises from outside
	// the function.
	dst := make([]string, len(s))
	copy(dst, s)
	sort.Strings(dst)
	b := new(bytes.Buffer)
	w := csv.NewWriter(b)
	w.Write(dst)
	w.Flush()
	// the csv library injects its own newline that we don't want.
	return strings.TrimRight(b.String(), "\n")
}

// CSVToSlice parses the provided CSV into a slice of strings.
func CSVToSlice(c string) []string {
	defer func() {
		if err := recover(); err != nil {
			log.Println(c)
			log.Panic(err)
		}
	}()
	if len(c) == 0 {
		return []string{}
	}
	r := csv.NewReader(strings.NewReader(c))
	s, err := r.Read()
	if err != nil {
		log.Panic(err)
	}
	// The CCADB has the habit of using ", " as a delimeter, which is
	// nice for human readability but breaks the CSV semantically.
	for i, v := range s {
		s[i] = strings.TrimSpace(v)
	}
	sort.Strings(s)
	return s
}

// MapCRLs trims the whitespace of each CR endpoint in the provided slice.
// If AllowLDAPCRLs is set to false, then LDAP CR endpoints are filtered
// from the return.
//
// Returns the slice translated to a CSV string.
func MapCRLs(c []string) string {
	crl := make([]string, 0)
	for _, url := range c {
		url = strings.TrimSpace(url)
		if AllowLDAPCRLs || !strings.HasPrefix(url, "ldap") {
			crl = append(crl, url)
		}
	}
	return SliceToCSV(crl)
}

// MapTime returns the string format of the provided Time
// using the TLS Observatory's time format.
func MapTime(t time.Time) string {
	return t.Format(ccadb.TimeFMT)
}
