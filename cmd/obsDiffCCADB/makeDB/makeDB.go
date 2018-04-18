package main

import (
	"flag"
	"log"
	"path"

	"github.com/mozilla/OneCRL-Tools/obsDiffCCADB/cmd"
)

const defaultLibraryDir = "../../../obsDiffCCADB"

var libraryDir string
var generatedContentDir string // generated
var help bool

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&libraryDir, "library", defaultLibraryDir, "Path to the obsDiffCCADB library.")
	flag.BoolVar(&help, "help", false, "Print usage.")
	generatedContentDir = path.Join(libraryDir, "generated")
}

func main() {
	flag.Parse()
	if help {
		flag.Usage()
		return
	}
	cmd.MakeDB(generatedContentDir)
}
