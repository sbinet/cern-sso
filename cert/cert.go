// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cert provides an easy way to add CERN certificates
// to a Go application.
package cert // import "github.com/sbinet/cern-sso/cert"

import (
	"crypto/x509"
	_ "embed"
	"fmt"
)

var (
	//go:embed cern-root-ca.crt
	rootPEM []byte
	//go:embed cern-grid-ca.crt
	gridPEM []byte
)

// RootPEM returns the CERN root certificate PEM data.
func RootPEM() []byte {
	return rootPEM
}

// CERNRootCertPool returns a new x509 pool certificate, seeded with
// the system cert pool and the CERN root certificate.
func CERNRootCertPool() *x509.CertPool {
	root := sysClone()
	root.AppendCertsFromPEM(rootPEM)
	return root
}

// GridPEM returns the CERN Grid certificate PEM data.
func GridPEM() []byte {
	return gridPEM
}

// GridCertPool returns a new x509 pool certificate, seeded with
// the system cert pool and the CERN Grid certificate.
func GridCertPool() *x509.CertPool {
	root := sysClone()
	root.AppendCertsFromPEM(gridPEM)
	return root
}

// var sys *x509.CertPool
//
// func init() {
// 	var err error
// 	sys, err = x509.SystemCertPool()
// 	if err != nil {
// 		panic(fmt.Errorf("cernca: could not load system cert pool: %+v", err))
// 	}
// }

func sysClone() *x509.CertPool {
	// FIXME(sbinet): remove when Go-1.19 is the last supported version.
	// and replace with simply sys.Clone()
	sys, err := x509.SystemCertPool()
	if err != nil {
		panic(fmt.Errorf("cernca: could not load system cert pool: %+v", err))
	}
	return sys
}
