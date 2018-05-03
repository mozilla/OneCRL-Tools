package cmd

import (
	"fmt"
	"os"
	"os/exec"
)

// BuildReportSite makes a system to call to the Hugo static
// site generator to build a copy of the report site.
func BuildReportSite(contentDir, destination string) error {
	p := exec.Command("which", "hugo")
	err := p.Run()
	if err != nil {
		return fmt.Errorf("Missing requirement, Hugo\nPlease visit https://gohugo.io/getting-started/installing/")
	}
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	os.Chdir(contentDir)
	defer os.Chdir(pwd)
	err := os.MkdirAll(destination)
	if err != nil {
		return err
	}
	p = exec.Command("hugo", "--buildDrafts", "--destination", destination)
	err = p.Run()
	if err != nil {
		fmt.Println(err)
	}
	return nil
}
