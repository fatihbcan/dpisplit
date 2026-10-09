package main

import (
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDoHLive(t *testing.T) {
	if os.Getenv("DOH_LIVE") == "" {
		t.Skip("set DOH_LIVE=1")
	}
	// Query: id 0x1234, RD, 1 question discord.com A IN
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'd', 'i', 's', 'c', 'o', 'r', 'd', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	ans, err := newDoHClient([]string{"8.8.8.8:443", "8.8.4.4:443"}, "dns.google").resolve(q)
	if err != nil {
		t.Fatal(err)
	}
	if ans[0] != 0x12 || ans[1] != 0x34 || ans[2]&0x80 == 0 || ans[7] == 0 {
		t.Fatalf("bad answer header % x", ans[:12])
	}
	t.Logf("got %d-byte answer, %d records", len(ans), ans[7])
}

// Local RFC 8484 server: checks method, headers and body; echoes a fixed answer.
func TestDoHAgainstLocalServer(t *testing.T) {
	q := []byte{0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 0, 1, 0, 1}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.URL.Path != "/dns-query" ||
			r.Header.Get("Content-Type") != "application/dns-message" || !bytes.Equal(body, q) {
			http.Error(w, "bad request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		// ID 0 as a caching server would send; client must restore it.
		w.Write([]byte{0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, 'x', 0, 0, 1, 0, 1})
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	dohRootCAs = x509.NewCertPool()
	dohRootCAs.AddCert(srv.Certificate())
	defer func() { dohRootCAs = nil }()

	addr := strings.TrimPrefix(srv.URL, "https://")
	// First endpoint is dead: client must fail over to the second.
	c := newDoHClient([]string{"127.0.0.1:1", addr}, "example.com")
	for i := 0; i < 3; i++ {
		ans, err := c.resolve(q)
		if err != nil {
			t.Fatal(err)
		}
		if ans[0] != 0xbe || ans[1] != 0xef || ans[7] != 1 {
			t.Fatalf("bad answer % x", ans)
		}
	}
}
