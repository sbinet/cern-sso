// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sso_test

import (
	"fmt"
	"log"

	sso "github.com/sbinet/cern-sso"
)

func ExampleLogin() {
	const url = "https://openstack.cern.ch"

	cli, err := sso.Login(url)
	if err != nil {
		log.Fatalf("could not log into %q: %+v", url, err)
	}
	defer cli.Close()

	for _, c := range cli.Cookies() {
		scheme := "http"
		if c.Secure {
			scheme = "https"
		}
		fmt.Printf("%-20s %s\n", c.Name+":", scheme+"://"+c.Domain+c.Path)
	}
}
