// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sso

import (
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/sbinet/cern-sso/cert"
	"golang.org/x/net/publicsuffix"
)

func httpClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig.RootCAs = cert.CERNRootCertPool()
	t.TLSClientConfig.RootCAs.AppendCertsFromPEM(cert.GridPEM())

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		panic(err)
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
		Jar:       jar,
	}
}
