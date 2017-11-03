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

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&libraryDir, "library", defaultLibraryDir, "Path to the obsDiffCCADB library.")
	generatedContentDir = path.Join(libraryDir, "generated")
}

func main() {
	cmd.MakeDB(generatedContentDir)
}
