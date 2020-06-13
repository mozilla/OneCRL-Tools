/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package auth

import "net/http"

// https://bugzilla.readthedocs.io/en/latest/api/core/v1/general.html#authentication
//
// An authenticator should take in an Header and append
// appropriate credential information into it.
//
// In general, these bindings prefer the approach of attaching authentication
// information to the header rather than the alternative of adding an API key
// to JSON encoded in the body.
type Authenticator interface {
	Authenticate(header http.Header)
}

type User struct {
	Username string
	Password string
}

func (u *User) Authenticate(header http.Header) {
	header.Set("X-BUGZILLA-LOGIN", u.Username)
	header.Set("X-BUGZILLA-PASSWORD", u.Password)
}

type ApiKey struct {
	ApiKey string
}

func (a *ApiKey) Authenticate(header http.Header) {
	header.Set("X-BUGZILLA-API-KEY", a.ApiKey)
}

type Token struct {
	Token string
}

func (t *Token) Authenticate(header http.Header) {
	header.Set("X-BUGZILLA-TOKEN", t.Token)
}

type Unauthenticated struct{}

func (n *Unauthenticated) Authenticate(_ http.Header) {}
