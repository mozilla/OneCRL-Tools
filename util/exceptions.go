/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package util

import (
  "encoding/json"
  "errors"
  "fmt"
  "github.com/mozilla/OneCRL-Tools/oneCRL"
  "io/ioutil"
  "net/http"
  "strings"
)

func getDataFromURL(url string) ([]byte, error) {
  r, _ := http.Get(url)
  defer r.Body.Close()

  return ioutil.ReadAll(r.Body)
}

func RecordExists(item oneCRL.Record, records *oneCRL.Records) bool {
  for _, record := range records.Data {
    if item.EqualsRecord(record) {
      return true
    }
  }
  return false
}

func LoadExceptions(location string, existing *oneCRL.Records, records *oneCRL.Records) error {
  res := new(oneCRL.Records)
  var data []byte

  if 0 != strings.Index(strings.ToUpper(location), "HTTP") {
    // if it's not an HTTP URL, attempt to load from a file
    if fileData, err := ioutil.ReadFile(location); nil != err {
      fmt.Printf("problem loading oneCRL exceptions from file %s\n", err)
    } else {
      data = fileData
    }
  } else {
    // ensure it's not an HTTP location
    if 0 != strings.Index(strings.ToUpper(location), "HTTPS") {
      return errors.New("Cowardly refusing to load exceptions from a non HTTPS location")
    }
    if resp, err := http.Get(location); nil != err {
      return err
    } else {
      defer resp.Body.Close()
      if urlData, err := ioutil.ReadAll(resp.Body); nil != err {
        return err
      } else {
        data = urlData
      }
    }
  }

  if err := json.Unmarshal(data, res); nil != err {
    return err
  }

  for idx := range res.Data {
    record := res.Data[idx]
    if !RecordExists(record, existing) {
      records.Data = append(records.Data, record)
    }
  }
  return nil
}
