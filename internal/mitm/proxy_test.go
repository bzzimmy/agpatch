package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"agpatch/agysp/internal/compose"
)

const target = "daily-cloudcode-pa.googleapis.com"

const body = `{"project":"p","request":{"contents":[],"systemInstruction":{"role":"user","parts":[{"text":"<identity>X</identity>"}]}},"requestType":"agent"}`

func TestProxyRewritesAndStreams(t *testing.T) {
	gotChunk1 := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "USER\\n\\n```harness_prompt\\n<identity>X</identity>\\n```") {
			t.Errorf("upstream got unrewritten body: %s", b)
		}
		if len(r.TransferEncoding) == 0 || r.TransferEncoding[0] != "chunked" {
			t.Errorf("expected chunked body, got TE=%v CL=%d", r.TransferEncoding, r.ContentLength)
		}
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("User-Agent") != "agy-test" || r.Host != target {
			t.Errorf("headers altered: %v host=%s", r.Header, r.Host)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-gotChunk1:
		case <-time.After(5 * time.Second):
			t.Error("client never saw first SSE chunk (buffered?)")
		}
		io.WriteString(w, "data: two\n\n")
	}))
	defer upstream.Close()

	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "tunnelled")
	}))
	defer other.Close()

	ca, err := LoadOrCreateCA(t.TempDir(), []string{target})
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]string{
		target + ":443":     upstream.Listener.Addr().String(),
		"other.example:443": other.Listener.Addr().String(),
	}
	var notes []string
	p := &Proxy{
		CA:    ca,
		Hosts: map[string]bool{target: true},
		Paths: []string{":streamGenerateContent"},
		Rewrite: func(r *http.Request, b []byte) ([]byte, string) {
			out, res, _ := compose.Apply(b, "USER", compose.Options{})
			if !res.Rewritten {
				return b, ""
			}
			return out, "rewrote"
		},
		Logf: func(f string, a ...any) { notes = append(notes, f) },
		DialContext: func(ctx context.Context, n, addr string) (net.Conn, error) {
			if to, ok := routes[addr]; ok {
				addr = to
			}
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		},
		UpstreamTLS: &tls.Config{RootCAs: pool(upstream.Certificate()), ServerName: "example.com"},
	}
	addr, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	purl, _ := url.Parse("http://" + addr)

	// Intercepted host: client trusts only our CA.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(purl), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	pr, pw := io.Pipe()
	go func() { io.WriteString(pw, body); pw.Close() }() // unknown length -> chunked
	req, _ := http.NewRequest("POST", "https://"+target+"/v1internal:streamGenerateContent?alt=sse", pr)
	req.Header.Set("User-Agent", "agy-test")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(resp.Body)
	line, _ := br.ReadString('\n')
	if line != "data: one\n" {
		t.Fatalf("first line %q", line)
	}
	close(gotChunk1)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: two") {
		t.Fatalf("missing second chunk: %q", rest)
	}
	resp.Body.Close()
	if len(notes) == 0 {
		t.Error("rewrite outcome was not logged")
	}

	// Non-intercepted host: TLS goes end to end with the real server's cert.
	c2 := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(purl),
		TLSClientConfig: &tls.Config{RootCAs: pool(other.Certificate()), ServerName: "example.com"}}}
	resp2, err := c2.Get("https://other.example/")
	if err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	if string(b2) != "tunnelled" {
		t.Fatalf("tunnel body %q", b2)
	}
}

func TestCANameConstraints(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir(), []string{target})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM)
	good, _ := ca.Leaf(target)
	if _, err := good.Leaf.Verify(x509.VerifyOptions{DNSName: target, Roots: roots}); err != nil {
		t.Fatalf("allowed host rejected: %v", err)
	}
	evil, _ := ca.Leaf("accounts.google.com")
	if _, err := evil.Leaf.Verify(x509.VerifyOptions{DNSName: "accounts.google.com", Roots: roots}); err == nil {
		t.Fatal("CA could mint a trusted cert outside its constraints")
	}
}

func pool(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}
