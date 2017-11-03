package cmd

import (
	"fmt"
	"os"
	"os/exec"
)

// BuildReportSite makes a system to call to the Hugo static
// site generator to build a copy of the report site.
func BuildReportSite(path, contentDir string) {
	p := exec.Command("which", "hugo")
	err := p.Run()
	if err != nil {
		fmt.Println("Missing requirement, Hugo\nPlease visit https://gohugo.io/getting-started/installing/")
		return
	}
	os.Chdir(path)
	p = exec.Command("hugo", "--buildDrafts", "--destination", contentDir)
	err = p.Run()
	if err != nil {
		fmt.Println(err)
	}
}
