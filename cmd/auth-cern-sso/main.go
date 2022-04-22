// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command auth-cern-sso authenticates with a CERN SSO protected site URL and
// stores cookies in a file, in the Netscape NTTP Cookie File format.
//
//	Usage: auth-cern-sso [options] -u <CERN SSO URL>
//
//	ex:
//	 $> auth-cern-sso -u https://example.cern.ch/login -o cookie.txt
//	 $> auth-cern-sso -u https://example.cern.ch/login -o cookie.txt -k
//
//	options:
//	  -a string
//	    	name of the authentication server (default "auth.cern.ch")
//	  -k	disable certificate verification (insecure)
//	  -o string
//	    	path to output cookie file (default "cookie.txt")
//	  -u string
//	    	CERN SSO protect site URL to authenticate against
package main // import "github.com/sbinet/cern-sso/cmd/auth-cern-sso"

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	sso "github.com/sbinet/cern-sso"
	"github.com/sbinet/mozcookie"
	"golang.org/x/net/publicsuffix"
)

func main() {
	log.SetPrefix("auth-cern-sso: ")
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: auth-cern-sso [options] -u <CERN SSO URL>

ex:
 $> auth-cern-sso -u https://example.cern.ch/login -o cookie.txt
 $> auth-cern-sso -u https://example.cern.ch/login -o cookie.txt -k

options:
`)
		flag.PrintDefaults()
	}

	var (
		login    = flag.String("u", "", "CERN SSO protect site URL to authenticate against")
		oname    = flag.String("o", "cookie.txt", "path to output cookie file")
		authSrv  = flag.String("a", "auth.cern.ch", "name of the authentication server")
		insecure = flag.Bool("k", false, "disable certificate verification (insecure)")
	)

	flag.Parse()

	if *login == "" {
		flag.Usage()
		log.Fatalf("missing URL value.")
	}

	err := xmain(*oname, *login, *authSrv, *insecure)
	if err != nil {
		log.Fatalf("could not run auth-cern-sso: %+v", err)
	}
}

func xmain(oname, login, auth string, insecure bool) error {
	if expire, ok := valid(oname, login, auth); ok {
		log.Printf("cookie file %q is still valid until %s.", oname, expire.UTC().Format("2006-01-02 15:04:05 (UTC)"))
		log.Printf("please use it instead of regenerating a cookie.")
		return nil
	}

	http, err := newClient(insecure)
	if err != nil {
		return fmt.Errorf("could not create HTTP client: %w", err)
	}

	cli, err := sso.Login(
		login,
		sso.WithAuthServer(auth),
		sso.WithClient(http),
		sso.WithLogger(log.Default()),
	)
	if err != nil {
		return fmt.Errorf("could not authenticate with %q: %w", login, err)
	}
	defer cli.Close()

	err = mozcookie.Write(oname, cli.Cookies())
	if err != nil {
		return fmt.Errorf("could not save cookies to %q: %w", oname, err)
	}

	return nil
}

func newClient(insecure bool) (*http.Client, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig.InsecureSkipVerify = insecure // FIXME(sbinet): use CERN Root-CA?

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create cookiejar: %w", err)
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: t,
		Jar:       jar,
	}, nil
}

func valid(oname, login, auth string) (time.Time, bool) {
	cookies, err := mozcookie.Read(oname)
	if err != nil {
		return time.Time{}, false
	}

	now := time.Now().UTC()
	cut := now.Add(10 * time.Minute)
	for _, c := range cookies {
		if c.Name != "KEYCLOAK_SESSION" {
			continue
		}
		if c.Expires.After(cut) {
			return c.Expires, true
		}
	}
	return time.Time{}, false
}
