package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/mozilla/OneCRL-Tools/ccadb"
	"github.com/mozilla/OneCRL-Tools/obsDiffCCADB/db"
)

const query = "SELECT * FROM %v WHERE `SHA-256 Fingerprint`=?"

var sha256 = regexp.MustCompile(`"([A-F0-9]{64})"`)
var contentRoot string

const diffTemplate = `
<!DOCTYPE html>
<html>
<body>
<a href="/">Home</a>
<h1>%v</h1>
<pre>
%v
</pre>
</body>
</html> 
`

const certTemplate = `
<div><a href="/">Home</a></div>
<div">
	<div><a href="https://crt.sh/?q=%v">crt.sh</a></div>
	<div><a href="/raw/?sha256=%v">Raw CCADB</a></div>
	<div><a href="https://lapo.it/asn1js/#%v">ASN.1 Decoder</a></div>
	<h2>CCADB</h2>
	<div><pre>%v</pre>
	</div></br>
	<h2>Observatory</h2>
    <div><pre>%v</pre></div>
</div>
`

const ccadbTemplate = `
<a href="/">Home</a>
<div">
	<pre>%v<pre>
</div>
`

func getDiff(fpath, certType string) (string, error) {
	f, err := os.Open(fpath)
	if err != nil {
		return "", err
	}
	d, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}
	// Inject links into the fingerprint for a "zoom in" UX.
	r := fmt.Sprintf(`<a href=/certificate/?sha256=$1&certType=%v>"$1"</a>`, certType)
	modded := string(sha256.ReplaceAll(d, []byte(r)))
	return fmt.Sprintf(diffTemplate, path.Base(fpath), modded), nil
}

func serveIntermediateDiffs(w http.ResponseWriter, r *http.Request) {
	fname := r.URL.Query().Get("fname")
	path := path.Join(contentRoot, "intermediate", fname)
	diff, err := getDiff(path, "intermediate")
	if err != nil {
		log.Println(err)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte(diff))
}

func serveRootDiffs(w http.ResponseWriter, r *http.Request) {
	fname := r.URL.Query().Get("fname")
	path := path.Join(contentRoot, "root", fname)
	diff, err := getDiff(path, "root")
	if err != nil {
		log.Println(err)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte(diff))
}

func serveCertificate(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			w.Write([]byte(fmt.Sprintf("%v", err)))
		}
	}()
	sha256 := r.URL.Query().Get("sha256")
	ct := r.URL.Query().Get("certType")
	certType := strings.ToUpper(string(ct[0])) + string(ct[1:])
	ccadbTable := fmt.Sprintf("ccadb%vNormalized", certType)
	obsTable := fmt.Sprintf("observatory%v", certType)
	var pem string
	var ccadbResult []byte
	var obsResult []byte
	var err error
	switch ct {
	case "root":
		c := db.ExecuteQueryOrPanicRoot(fmt.Sprintf(query, ccadbTable), sha256)[0]
		o := db.ExecuteQueryOrPanicRoot(fmt.Sprintf(query, obsTable), sha256)[0]
		ccadbResult, err = json.MarshalIndent(c, "", "    ")
		if err != nil {
			log.Println(err)
			w.Write([]byte(err.Error()))
			return
		}
		obsResult, err = json.MarshalIndent(o, "", "    ")
		if err != nil {
			log.Println(err)
			w.Write([]byte(err.Error()))
			return
		}
		if err != nil {
			log.Println(err)
			w.Write([]byte(err.Error()))
			return
		}
		pem = o.PEMInfo
	case "intermediate":
		c := db.ExecuteQueryOrPanicIntermediate(fmt.Sprintf(query, ccadbTable), sha256)[0]
		o := db.ExecuteQueryOrPanicIntermediate(fmt.Sprintf(query, obsTable), sha256)[0]
		ccadbResult, err = json.MarshalIndent(c, "", "    ")
		if err != nil {
			log.Println(err)
			w.Write([]byte(err.Error()))
			return
		}
		obsResult, err = json.MarshalIndent(o, "", "    ")
		if err != nil {
			log.Println(err)
			w.Write([]byte(err.Error()))
			return
		}
		if err != nil {
			log.Println(err)
			w.Write([]byte(err.Error()))
			return
		}
		pem = o.PEMInfo
	}
	html := fmt.Sprintf(certTemplate, sha256, sha256, pem, string(ccadbResult), string(obsResult))
	w.Write([]byte(html))
}

func serveCCADB(w http.ResponseWriter, r *http.Request) {
	sha256 := r.URL.Query().Get("sha256")
	c, ok := CCADB[sha256]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	j, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte(fmt.Sprintf(ccadbTemplate, string(j))))
}

// CCADB is an in memory copy of the CCADB retrieved at startup.
// Used provide a raw, unaltered, form of the CCADB in the UI.
var CCADB = map[string]*ccadb.Certificate{}

func getFullCCADB() {
	req, err := http.NewRequest("GET", ccadb.IntermediateReportURL, nil)
	if err != nil {
		log.Panic(err)
	}
	req.Header.Add("X-Automated-Tool", `https://github.com/mozilla/OneCRL-Tools obsDiffCCADB"`)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Panic(err)
	}
	defer res.Body.Close()
	intermediates, err := ccadb.Parse(res.Body)
	if err != nil {
		log.Panic(err)
	}

	req2, err := http.NewRequest("GET", ccadb.RootReportURL, nil)
	if err != nil {
		log.Panic(err)
	}
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		log.Panic(err)
	}
	defer res2.Body.Close()
	roots, err := ccadb.Parse(res2.Body)
	if err != nil {
		log.Panic(err)
	}

	for _, c := range intermediates {
		CCADB[strings.Replace(c.GetOrPanic("SHA-256 Fingerprint"), ":", "", -1)] = c
	}
	for _, c := range roots {
		CCADB[strings.Replace(c.GetOrPanic("SHA-256 Fingerprint"), ":", "", -1)] = c
	}
}

func setup(contentDir string) {
	log.Println("Getting live copy of ccadb..")
	getFullCCADB()
	db.Initialize(db.DontWipe, contentDir)
	log.Println("Serving content from: ", contentDir)
	contentRoot = contentDir
	http.Handle("/", http.FileServer(http.Dir(path.Join(contentDir, "public"))))
	http.HandleFunc("/intermediate/", serveIntermediateDiffs)
	http.HandleFunc("/root/", serveRootDiffs)
	http.HandleFunc("/certificate/", serveCertificate)
	http.HandleFunc("/raw/", serveCCADB)
}

// ServeReportSiteTLS serves the provided static content over the provided port
// over TLS using the provided certificate and private key.
func ServeReportSiteTLS(contentDir, cert, private string, port int) {
	setup(contentDir)
	log.Printf("Listening on port %v\n", port)
	go func() {
		if err := http.ListenAndServe(":80", http.RedirectHandler("https://ccadb.chenderson.org", http.StatusTemporaryRedirect)); err != nil {
			log.Println(err)
		}
	}()
	if err := http.ListenAndServeTLS(":443", cert, private, nil); err != nil {
		log.Println(err)
	}
}

// ServeReportSite serves the provided static content over the provdided port in plaintext.
func ServeReportSite(contentDir string, port int) {
	setup(contentDir)
	log.Printf("Listening on port %v\n", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil); err != nil {
		log.Println(err)
	}
}
