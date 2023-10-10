// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sso // import "github.com/sbinet/cern-sso"

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
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
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("auth-server-allowlist", "auth.cern.ch,login.cern.ch"),
		chromedp.UserAgent(`Go/1.x`),
	)
	var ctx = context.Background()
	ctx, cancel1 := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel1()

	ctx, cancel2 := chromedp.NewContext(ctx, chromedp.WithLogf(cli.msg.Printf))
	//ctx, cancel2 := chromedp.NewContext(ctx, chromedp.WithDebugf(cli.msg.Printf))
	defer cancel2()

	err := chromedp.Run(ctx,
		chromedp.Navigate(cli.root),
		chromedp.Click(`a[id="social-kerberos"]`, chromedp.ByQuery),
		waitVisible(5*time.Second, `h1`, chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := network.GetCookies().Do(ctx)
			if err != nil {
				return fmt.Errorf("sso: could not retrieve cookies: %w", err)
			}
			cli.cs = cli.cs[:0]
			for _, p := range []string{
				cli.root,
				"https://" + cli.srv + "/auth/realms/cern/",
				"https://" + cli.srv + "/auth/realms/kerberos/",
			} {
				ep, err := url.Parse(p)
				if err != nil {
					return fmt.Errorf("sso: could not parse url %q: %w", p, err)
				}
				var cs []*http.Cookie
				for _, c := range cookies {
					o := cookieFrom(*c, cli.exp)
					cs = append(cs, o)
				}
				cli.http.Jar.SetCookies(ep, cs)
				cli.cs = cs
			}

			return nil
		}),
	)
	if err != nil {
		return fmt.Errorf("could not authenticate with %q: %w", cli.root, err)
	}

	if true {
		return nil
	}

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

func cookieFrom(c network.Cookie, exp time.Duration) *http.Cookie {
	var samesite http.SameSite
	switch c.SameSite {
	case network.CookieSameSiteStrict:
		samesite = http.SameSiteStrictMode
	case network.CookieSameSiteLax:
		samesite = http.SameSiteLaxMode
	case network.CookieSameSiteNone:
		samesite = http.SameSiteNoneMode
	default:
		samesite = http.SameSiteDefaultMode
	}

	var expires time.Time
	switch {
	case c.Expires == 0:
		expires = time.Now().UTC().Add(exp)
	default:
		expires = time.Unix(int64(c.Expires), 0).UTC()
	}

	return &http.Cookie{
		Name:     c.Name,
		Value:    c.Value,
		Path:     c.Path,
		Domain:   c.Domain,
		Expires:  expires,
		Secure:   c.Secure,
		HttpOnly: c.HTTPOnly,
		SameSite: samesite,
	}
}

func waitVisible(timeout time.Duration, sel string, opts ...chromedp.QueryOption) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		sub, done := context.WithTimeout(ctx, timeout)
		defer done()

		err := chromedp.WaitVisible(sel, opts...).Do(sub)
		if err != nil {
			log.Printf("wait-visible %q timed out: %+v", sel, err)
		}
		return err
	})
}
