/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package bugs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/mozilla/OneCRL-Tools/config"
	"net/http"
	"net/url"
)

type AttachmentFlag struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Requestee string `json:"requestee"`
	New       bool   `json:"new"`
}

type Attachment struct {
	ApiKey      string           `json:"api_key"`
	Ids         []int            `json:"ids"`
	ContentType string           `json:"content_type"`
	Data        string           `json:"data"`
	Summary     string           `json:"summary"`
	FileName    string           `json:"file_name"`
	Flags       []AttachmentFlag `json:"flags"`
	BugId       int              `json:"bug_id"`
	Comment     string           `json:"comment"`
}

type AttachmentResponse struct {
	Ids []string `json:"ids"`
}

type Bug struct {
	ApiKey      string `json:"api_key"`
	Product     string `json:"product"`
	Component   string `json:"component"`
	Version     string `json:"version"`
	Summary     string `json:"summary"`
	Comment     string `json:"comment"`
	Description string `json:"description"`
	Blocks      []int  `json:"blocks,omitempty"`
}

type BugResponse struct {
	Id int `json:"id"`
}

const getBugDataIncludeFields string = "id,summary"

type SearchResponse struct {
	Bugs []BugData `json:"bugs"`
}

type BugData struct {
	Summary string `json:"summary"`
	Id      int    `json:"id"`
}

func CreateBug(bug Bug, conf *config.OneCRLConfig) (int, error) {
	// POST the bug
	bugNum := -1
	url := conf.BugzillaBase + "/rest/bug"
	marshalled, err := json.Marshal(bug)
	if "yes" == conf.OneCRLVerbose {
		fmt.Printf("POSTing %s to %s\n", marshalled, url)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(marshalled))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return bugNum, err
	}
	if "yes" == conf.OneCRLVerbose {
		fmt.Printf("status code is %d\n", resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)
	var response BugResponse
	err = dec.Decode(&response)
	if err != nil {
		return bugNum, err
	} else {
		bugNum = response.Id

		fmt.Printf("%s\n", err)
		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("%v\n", response.Id)
		}
	}
	defer resp.Body.Close()

	return bugNum, nil
}

func AttachToBug(bugNum int, apiKey string, attachments []Attachment, conf *config.OneCRLConfig) error {
	// loop over the attachments, add each to the bug
	for _, attachment := range attachments {
		attUrl := fmt.Sprintf(conf.BugzillaBase+"/rest/bug/%d/attachment", bugNum)
		attachment.Ids = []int{bugNum}
		attachment.ApiKey = apiKey
		attachment.BugId = bugNum
		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("Attempting to marshal %v\n", attachment)
		}
		attMarshalled, err := json.Marshal(attachment)
		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("POSTing %s to %s\n", attMarshalled, attUrl)
		}
		attReq, err := http.NewRequest("POST", attUrl, bytes.NewBuffer(attMarshalled))
		attReq.Header.Set("Content-Type", "application/json")
		attClient := &http.Client{}
		attResp, err := attClient.Do(attReq)
		if err != nil {
			return err
		}
		if "yes" == conf.OneCRLVerbose {
			fmt.Printf("att response %s\n", attResp)
		}
	}
	return nil
}

func GetBugData(bugNumStrings []string, conf *config.OneCRLConfig) (SearchResponse, error) {
	var response SearchResponse
	bugNumString := ""
	for _, bugNum := range bugNumStrings {
		if 0 != len(bugNumString) {
			bugNumString = fmt.Sprintf("%s,%s", bugNumString, bugNum)
		} else {
			bugNumString = bugNum
		}
	}

	getUrl := fmt.Sprintf(conf.BugzillaBase+"/rest/bug?id=%s&include_fields=%s",
		url.QueryEscape(bugNumString), url.QueryEscape(getBugDataIncludeFields))

	getReq, err := http.NewRequest("GET", getUrl, nil)

	client := &http.Client{}
	resp, err := client.Do(getReq)

	if err != nil {
		return response, err
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&response)

	defer resp.Body.Close()

	return response, err
}
