// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sso // import "github.com/sbinet/cern-sso"

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/net/html"
)

// Login simulates a browser session to log in with the provided URL, using
// the SPNEGO protocol.
func Login(url string, opts ...Option) (*Client, error) {
	cli, err := newClient(url, opts)
	if err != nil {
		return nil, fmt.Errorf("sso: could not create options for %q: %w", url, err)
	}

	err = cli.Login()
	if err != nil {
		return nil, fmt.Errorf("sso: could not login with %q: %w", url, err)
	}

	return cli, nil
}

// Login attempts to login with the client login page.
func (cli *Client) Login() error {
	req, err := http.NewRequest(http.MethodGet, cli.root, nil)
	if err != nil {
		return fmt.Errorf("sso: could not create GET request to %q: %w", cli.root, err)
	}
	req.Header.Set("User-Agent", "Go/1.x")
	req.Header.Set("Accept", "*/*")

	resp, err := cli.spn.Do(req)
	if err != nil {
		return fmt.Errorf("sso: could not send GET request to %q: %w", cli.root, err)
	}
	defer resp.Body.Close()

	krbURL, err := extractKrb5URL(cli.srv, resp.Body)
	if err != nil {
		return fmt.Errorf("sso: could not extract kerberos5 URL from GET response to %q: %w", cli.root, err)
	}

	req, err = http.NewRequest(http.MethodGet, krbURL, nil)
	if err != nil {
		return fmt.Errorf("sso: could not create GET krb5-auth request: %w", err)
	}

	resp, err = cli.spn.Do(req)
	if err != nil {
		return fmt.Errorf("sso: could not send GET krb5-auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sso: could not login (status=%s (%d))", resp.Status, resp.StatusCode)
	}

	page, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("sso: could not read krb5-auth page: %w", err)
	}

	if bytes.Contains(page, []byte(`form name="saml-post-binding"`)) {
		err = cli.handleSAML(page)
		if err != nil {
			return fmt.Errorf("sso: could not read login response: %w", err)
		}
	}

	err = cli.setCookies()
	if err != nil {
		return fmt.Errorf("sso: could not store cookies: %w", err)
	}

	return nil
}

func extractKrb5URL(srv string, r io.Reader) (string, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("sso: could not read HTML payload: %w", err)
	}

	doc, err := html.Parse(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("sso: could not parse HTML: %w", err)
	}

	var (
		f   func(n *html.Node)
		btn *html.Node
	)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == "social-kerberos" {
					btn = n
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	if btn == nil {
		return "", fmt.Errorf("sso: could not find kerberos button in:\n%s", raw)
	}

	var href string
	for _, attr := range btn.Attr {
		if attr.Key == "href" {
			href = attr.Val
		}
	}

	if href == "" {
		return "", fmt.Errorf("could not find kerberos href")
	}

	return "https://" + srv + href, nil
}
