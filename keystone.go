// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sso // import "github.com/sbinet/cern-sso"

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (cli *Client) handleKeystone(u *url.URL) error {
	form := make(url.Values)
	toks := strings.Split(u.Fragment, "&")
	for i := range toks {
		tok := strings.Replace(toks[i], "+", " ", -1)
		idx := strings.Index(tok, "=")
		if idx < 0 {
			return fmt.Errorf("sso: malformed query (missing '=')")
		}
		k := tok[:idx]
		v := tok[idx+1:]
		form.Add(k, v)
	}

	action := u.Scheme + "://" + u.Host + u.Path
	req, err := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("could not create KeyStone request to %q: %w", action, err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := cli.http.Do(req)
	if err != nil {
		return fmt.Errorf("could not send KeyStone request: %w", err)
	}
	defer resp.Body.Close()

	return nil
}
