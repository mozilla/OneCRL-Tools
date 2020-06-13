/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package auth

import (
	"fmt"
	"net/http"

	"github.com/mozilla/OneCRL-Tools/kinto/api"
)

// https://docs.kinto-storage.org/en/stable/api/1.x/authentication.html
type Authenticator interface {
	Authenticate(r *http.Request)
}

type User struct {
	Username string `json:"-"`
	Password string `json:"password"`
	*api.Record
}

func (u *User) Put() string {
	return fmt.Sprintf("/accounts/%s", u.Username)
}

func (u *User) Authenticate(r *http.Request) {
	r.SetBasicAuth(u.Username, u.Password)
}

type Token struct {
	Token string
}

func (t *Token) Authenticate(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+t.Token)
}

type Unauthenticated struct{}

func (n *Unauthenticated) Authenticate(_ *http.Request) {}
