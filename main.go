// Copyright 2023 Robin Zhong
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/chzyer/readline"
)

func main() {
	var (
		caCert     string
		clientKey  string
		clientCert string
		serverName string
		help       bool
	)

	flag.StringVar(&caCert, "ca", caCert, "the certification file of remote readline repl server")
	flag.StringVar(&clientCert, "cert", clientCert, "the client certification")
	flag.StringVar(&clientKey, "key", clientKey, "the key of client certification")
	flag.StringVar(&serverName, "servername", serverName, "the override server name during tls handshaking")
	flag.BoolVar(&help, "h", help, "show help")

	flag.Parse()

	if flag.NArg() == 0 || help {
		fmt.Println("Usage: readline-cli [options] <tcp/tls>://<host>:<port>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var (
		host   = flag.Args()[0]
		dialer = &net.Dialer{
			Timeout: 5 * time.Second,
		}
		conn net.Conn
		err  error
	)

	u, err := url.Parse(host)
	if err != nil {
		u, err = url.Parse("tcp://" + host)
	}
	if err != nil {
		log.Fatal("invalid host: ", err)
		return
	}

	if u.Scheme == "tls" {
		tlsConfig := &tls.Config{}
		if caCert != "" {
			pemContent, err := os.ReadFile(caCert)
			if err != nil {
				log.Fatal("loading ca cert file failed: ", err)
				return
			}
			tlsConfig.RootCAs = x509.NewCertPool()
			tlsConfig.RootCAs.AppendCertsFromPEM(pemContent)
		}
		if clientCert != "" && clientKey != "" {
			cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
			if err != nil {
				log.Fatal("loading client cert failed: ", err)
				return
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		if serverName != "" {
			tlsConfig.ServerName = serverName
		} else {
			tlsConfig.ServerName = u.Hostname()
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", u.Host, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", u.Host)
	}

	if err != nil {
		log.Fatal(err)
		return
	}

	defer conn.Close()

	cli, err := readline.NewRemoteCli(conn)
	if err != nil {
		log.Fatal(err)
		return
	}
	_ = cli.Serve()
}
