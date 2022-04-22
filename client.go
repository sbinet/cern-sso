// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sso

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	krb5 "github.com/jcmturner/gokrb5/v8/client"
)

const (
	DefaultAuthServer = "auth.cern.ch" // Default authentication server name.
)

type Option func(opt *Client) error

// WithClient configures the authentication to use the passed HTTP client.
func WithClient(cli *http.Client) Option {
	return func(o *Client) error {
		o.http = cli
		return nil
	}
}

// WithAuthServer configures the authentication to use the passed
// authentication server name.
//
// ex:
//
//	"auth.cern.ch"
func WithAuthServer(srv string) Option {
	return func(o *Client) error {
		o.srv = srv
		return nil
	}
}

// WithLogger configures the authentication to use the passed logger.
func WithLogger(msg *log.Logger) Option {
	return func(o *Client) error {
		o.msg = msg
		return nil
	}
}

// WithKrb5 configures the authentication to user the provided
// kerberos5 client.
func WithKrb5(cli *krb5.Client) Option {
	return func(o *Client) error {
		o.krb5 = cli
		return nil
	}
}

// Client is a Single Sign-On client.
type Client struct {
	root string // login server
	srv  string // auth server
	http *http.Client
	krb5 *krb5.Client
	cs   []*http.Cookie

	msg   *log.Logger
	delta time.Duration // minimum validity time left for cookie
}

// NewClient creates a new SSO client that will authenticate with the
// provided login page.
// The returned client is not yet authenticated: one should use the
// Login method to do so.
func NewClient(login string, opts ...Option) (*Client, error) {
	return newClient(login, opts)
}

func newClient(root string, opts []Option) (*Client, error) {
	cli := &Client{
		root:  root,
		srv:   DefaultAuthServer,
		http:  httpClient(),
		delta: 10 * time.Minute,
		msg:   log.Default(),
	}
	for _, o := range opts {
		err := o(cli)
		if err != nil {
			return nil, fmt.Errorf("sso: could not apply option: %w", err)
		}
	}

	if cli.krb5 == nil {
		k, err := newKrb5Client(cli.msg)
		if err != nil {
			return nil, fmt.Errorf("sso: could not create kerberos5 client: %w", err)
		}
		cli.krb5 = k
	}

	return cli, nil
}

func (cli *Client) Close() error {
	if cli.krb5 != nil {
		cli.krb5.Destroy()
		cli.krb5 = nil
	}

	return nil
}

func (cli *Client) setCookies() error {
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
		cs := cli.http.Jar.Cookies(ep)
		for _, c := range cs {
			c.Domain = ep.Host
			c.Path = ep.Path
			c.Secure = ep.Scheme == "https"
			if c.Expires.IsZero() {
				c.Expires = time.Now().UTC().Add(6 * time.Hour)
			}
		}
		cli.cs = append(cli.cs, cs...)
	}

	return nil
}

// Valid returns whether the Keycloak cookie is valid, and its expiration date.
func (cli *Client) Valid() (time.Time, bool) {
	cut := time.Now().UTC().Add(cli.delta)
	for _, c := range cli.cs {
		if c.Name != "KEYCLOAK_SESSION" {
			continue
		}
		if c.Expires.After(cut) {
			return c.Expires, true
		}
	}
	return time.Time{}, false
}

func (cli *Client) Cookies() []*http.Cookie {
	return cli.cs
}