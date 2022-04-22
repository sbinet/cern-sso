// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sso

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

func (cli *Client) handleSAML(page []byte) error {
	var (
		parse func(n *html.Node)
		post  *html.Node
	)
	doc, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		return fmt.Errorf("could not parse page: %w", err)
	}

	parse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == "saml-post-binding" {
					post = n
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			parse(c)
		}
	}

	parse(doc)
	if post == nil {
		return fmt.Errorf("could not find SAML post form")
	}

	var (
		saml  *html.Node
		relay *html.Node
	)
	parse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == "SAMLResponse" {
					saml = n
				}
				if attr.Key == "name" && attr.Val == "RelayState" {
					relay = n
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			parse(c)
		}
	}
	parse(post)
	if saml == nil {
		return fmt.Errorf("could not find SAML input form")
	}
	if relay == nil {
		return fmt.Errorf("could not find relay input form")
	}

	form := make(url.Values)
	for _, attr := range saml.Attr {
		if attr.Key != "value" {
			continue
		}
		form.Add("SAMLResponse", attr.Val)
		break
	}

	for _, attr := range relay.Attr {
		if attr.Key != "value" {
			continue
		}
		form.Add("RelayState", attr.Val)
		continue
	}

	var action string
	for _, attr := range post.Attr {
		if attr.Key != "action" {
			continue
		}
		action = attr.Val
		break
	}

	req, err := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("could not create SAML request to %q: %w", action, err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := cli.spn.Do(req)
	if err != nil {
		return fmt.Errorf("could not send SAML request: %w", err)
	}
	defer resp.Body.Close()

	return nil
}
