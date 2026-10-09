package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// DNS-over-HTTPS client pinned to Google's resolver IPs.
//
// It dials 8.8.8.8 / 8.8.4.4 directly (never looks up "dns.google" through the
// system resolver, which this program itself intercepts) and verifies the TLS
// certificate for dns.google, so the ISP can neither read nor fake answers.

// dohRootCAs is nil (system roots) except in tests.
var dohRootCAs *x509.CertPool

type dohClient struct {
	http *http.Client
	url  string
}

// addrs are "ip:port" endpoints of the resolver; host is its TLS name.
func newDoHClient(addrs []string, host string) *dohClient {
	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}
	var next atomic.Int32
	tr := &http.Transport{
		Proxy: nil, // never route DNS through a proxy
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			start := int(next.Load())
			for i := 0; i < len(addrs); i++ {
				c, err := dialer.DialContext(ctx, "tcp", addrs[(start+i)%len(addrs)])
				if err == nil {
					return c, nil
				}
				lastErr = err
				next.Store(int32((start + i + 1) % len(addrs))) // prefer the other server next time
			}
			return nil, lastErr
		},
		TLSClientConfig:     &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: dohRootCAs},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &dohClient{
		http: &http.Client{Transport: tr, Timeout: 6 * time.Second},
		url:  "https://" + host + "/dns-query",
	}
}

// resolve sends a raw DNS query (wire format, RFC 8484) and returns the raw
// answer with the transaction ID restored to the caller's.
func (d *dohClient) resolve(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("query too short")
	}
	req, err := http.NewRequest(http.MethodPost, d.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status %d", resp.StatusCode)
	}
	ans, err := io.ReadAll(io.LimitReader(resp.Body, 65000))
	if err != nil {
		return nil, err
	}
	if len(ans) < 12 {
		return nil, errors.New("DoH answer too short")
	}
	ans[0], ans[1] = query[0], query[1]
	return ans, nil
}
