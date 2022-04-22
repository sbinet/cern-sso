// Copyright ©2022 The cern-sso Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sso

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	krb5cli "github.com/jcmturner/gokrb5/v8/client"
	krb5cfg "github.com/jcmturner/gokrb5/v8/config"
	krb5cred "github.com/jcmturner/gokrb5/v8/credentials"
)

const configPath = "/etc/krb5.conf"

func cachePath() string {
	if v := os.Getenv("KRB5CCNAME"); v != "" {
		return strings.TrimLeft(v, "FILE:")
	}

	usr, err := user.Current()
	if err != nil {
		return ""
	}

	v := filepath.Join(os.TempDir(), fmt.Sprintf("krb5cc_%s", usr.Uid))
	return v
}

func newKrb5Client(msg *log.Logger) (*krb5cli.Client, error) {
	cfg, err := krb5cfg.Load(configPath)
	if err != nil {
		switch err.(type) {
		case krb5cfg.UnsupportedDirective:
			// ok. just ignore it.
		default:
			return nil, fmt.Errorf("sso: could not load kerberos-5 configuration: %w", err)
		}
	}

	cred, err := krb5cred.LoadCCache(cachePath())
	if err != nil {
		return nil, fmt.Errorf("sso: could not load kerberos-5 cached credentials: %w", err)
	}

	krb, err := krb5cli.NewFromCCache(
		cred, cfg,
		krb5cli.Logger(msg),
		krb5cli.DisablePAFXFAST(true),
		krb5cli.AssumePreAuthentication(false),
	)
	if err != nil {
		return nil, fmt.Errorf("sso: could not create kerberos-5 client from cached credentials: %w", err)
	}

	return krb, nil
}
