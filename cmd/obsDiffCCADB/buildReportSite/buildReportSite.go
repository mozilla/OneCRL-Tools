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

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&libraryDir, "library", defaultLibraryDir, "Path to the obsDiffCCADB library.")
	generatedContentDir = path.Join(libraryDir, "generated")
	recommendationDir = path.Join(libraryDir, "recommendation")
	staticContentDir = path.Join(generatedContentDir, "public")
}

func main() {
	cmd.BuildReportSite(recommendationDir, staticContentDir)
}
