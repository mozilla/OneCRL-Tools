package main

import (
	"flag"
	"log"
	"path"

	"github.com/mozilla/OneCRL-Tools/obsDiffCCADB/cmd"
)

const defaultLibraryDir = "../../obsDiffCCADB"

var libraryDir string
var generatedContentDir string // generated
var recommendationDir string   // generated/recommendation
var staticContentDir string    // generated/public
var port int
var tls bool
var cert string
var privKey string

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&libraryDir, "library", defaultLibraryDir, "Path to the obsDiffCCADB library.")
	flag.IntVar(&port, "port", 1025, "Port to listen on.")
	flag.BoolVar(&tls, "tls", false, "Whether or not to serve content over TLS.")
	flag.StringVar(&cert, "cert", "", "Path to the cert to use when using TLS.")
	flag.StringVar(&privKey, "key", "", "Path to the private key to use when using TLS.")

	generatedContentDir = path.Join(libraryDir, "generated")
	recommendationDir = path.Join(libraryDir, "recommendation")
	staticContentDir = path.Join(generatedContentDir, "public")
}

func main() {
	log.Println("Pulling and normalizing data from CCADB and the TLS Observatory...")
	cmd.MakeDB(generatedContentDir)
	log.Println("Building difference report...")
	cmd.BuildDiffReport(generatedContentDir)
	log.Println("Building static site...")
	cmd.BuildReportSite(recommendationDir, staticContentDir)
	if tls {
		log.Println("Serving report over TLS...")
		cmd.ServeReportSiteTLS(generatedContentDir, cert, privKey, port)
	} else {
		log.Println("Serving report...")
		cmd.ServeReportSite(generatedContentDir, port)
	}
}
