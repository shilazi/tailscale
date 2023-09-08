// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// synology.go contains handlers and logic, such as authentication,
// that is specific to running the web client on Synology.

package web

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"tailscale.com/tsweb"
	"tailscale.com/util/groupmember"
)

// authorizeSynology authenticates the logged-in Synology user and verifies
// that they are authorized to use the web client.
// It returns true if the request is authorized to continue, and false otherwise.
// If false, an error may also be returned which should be reported to users.
func authorizeSynology(w http.ResponseWriter, r *http.Request) (ok bool, _ *tsweb.HTTPError) {
	if synoTokenRedirect(w, r) {
		return false, nil
	}

	// authenticate the Synology user
	cmd := exec.Command("/usr/syno/synoman/webman/modules/authenticate.cgi")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, &tsweb.HTTPError{Err: fmt.Errorf("auth: %v: %s", err, out), Code: http.StatusUnauthorized}
	}
	user := strings.TrimSpace(string(out))

	// check if the user is in the administrators group
	isAdmin, err := groupmember.IsMemberOfGroup("administrators", user)
	if err != nil {
		return false, &tsweb.HTTPError{Err: err, Code: http.StatusForbidden}
	}
	if !isAdmin {
		return false, &tsweb.HTTPError{Err: errors.New("not a member of administrators group"), Code: http.StatusForbidden}
	}

	return true, nil
}

func synoTokenRedirect(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Syno-Token") != "" {
		return false
	}
	if r.URL.Query().Get("SynoToken") != "" {
		return false
	}
	if r.Method == "POST" && r.FormValue("SynoToken") != "" {
		return false
	}
	// We need a SynoToken for authenticate.cgi.
	// So we tell the client to get one.
	_, _ = fmt.Fprint(w, synoTokenRedirectHTML)
	return true
}

const synoTokenRedirectHTML = `<html>
Redirecting with session token...
<script>
  fetch("/webman/login.cgi")
    .then(r => r.json())
    .then(data => {
	u = new URL(window.location)
	u.searchParams.set("SynoToken", data.SynoToken)
	document.location = u
    })
</script>
`
