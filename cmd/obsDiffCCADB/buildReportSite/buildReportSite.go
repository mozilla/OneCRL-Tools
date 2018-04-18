package main

import (
	"flag"
	"fmt"
	"log"
	"path"
	"path/filepath"

	"github.com/mozilla/OneCRL-Tools/obsDiffCCADB/cmd"
)

const defaultLibraryDir = "../../../obsDiffCCADB"

var libraryDir string
var generatedContentDir string // generated
var recommendationDir string   // generated/recommendation
var staticContentDir string    // generated/public
var help bool

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&libraryDir, "library", defaultLibraryDir, "Path to the obsDiffCCADB library.")
	flag.BoolVar(&help, "help", false, "Print usage.")
	generatedContentDir = path.Join(libraryDir, "generated")
	var err error
	recommendationDir, err = filepath.Abs(path.Join(libraryDir, "recommendation"))
	if err != nil {
		log.Panicln(err)
	}
	staticContentDir, err = filepath.Abs(path.Join(generatedContentDir, "public"))
	if err != nil {
		log.Panicln(err)
	}
}

func main() {
	flag.Parse()
	if help {
		flag.Usage()
		return
	}
	if err := cmd.BuildReportSite(recommendationDir, staticContentDir); err != nil {
		fmt.Println(err)
	}
}
