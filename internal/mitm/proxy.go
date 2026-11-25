// Package mitm is a minimal HTTPS proxy. CONNECT requests for a fixed set of
// hosts are terminated locally so request bodies can be rewritten. Every other
// host is relayed as an opaque TCP tunnel and never decrypted.
package mitm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RewriteFunc receives the decoded body of a selected POST and returns the
// body to send upstream plus a short note for the log ("" means unchanged).
type RewriteFunc func(r *http.Request, body []byte) (out []byte, note string)

type Proxy struct {
	CA       *Authority
	Hosts    map[string]bool // hosts to intercept (port 443 only)
	Paths    []string        // URL path suffixes whose POST bodies go to Rewrite
	Rewrite  RewriteFunc
	Upstream *url.URL // optional upstream HTTP proxy to chain through
	Logf     func(format string, args ...any)

	// Test hooks.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	UpstreamTLS *tls.Config

	initOnce  sync.Once
	transport *http.Transport
}

const maxBody = 256 << 20

var quiet = log.New(io.Discard, "", 0)

// Start listens on 127.0.0.1 with an ephemeral port and serves in the background.
func (p *Proxy) Start() (string, error) {
	p.init()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: http.HandlerFunc(p.serveProxy), ErrorLog: quiet, ReadHeaderTimeout: 30 * time.Second}
	go srv.Serve(ln)
	return ln.Addr().String(), nil
}

func (p *Proxy) init() {
	p.initOnce.Do(func() {
		if p.Logf == nil {
			p.Logf = func(string, ...any) {}
		}
		dial := p.DialContext
		if dial == nil {
			dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		}
		p.DialContext = dial
		t := &http.Transport{
			DialContext:         dial,
			TLSClientConfig:     p.UpstreamTLS,
			TLSHandshakeTimeout: 20 * time.Second,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
			// agy speaks HTTP/1.1 to this backend; keep it that way.
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		}
		if p.Upstream != nil {
			t.Proxy = http.ProxyURL(p.Upstream)
		}
		p.transport = t
	})
}

func (p *Proxy) serveProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "agy-sp proxy: only CONNECT is supported", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	c := bufferedConn(conn, brw.Reader)
	if p.Hosts[strings.ToLower(host)] && port == "443" {
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		p.serveMITM(c, strings.ToLower(host))
		return
	}
	p.tunnel(c, r.Host)
}

// tunnel relays bytes untouched to target.
func (p *Proxy) tunnel(client net.Conn, target string) {
	defer client.Close()
	up, err := p.dial(context.Background(), target)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(up, client)
	go cp(client, up)
	<-done
	<-done
}

func (p *Proxy) dial(ctx context.Context, target string) (net.Conn, error) {
	if p.Upstream == nil {
		return p.DialContext(ctx, "tcp", target)
	}
	if p.Upstream.Scheme != "http" {
		return nil, fmt.Errorf("upstream proxy scheme %q unsupported", p.Upstream.Scheme)
	}
	addr := p.Upstream.Host
	if p.Upstream.Port() == "" {
		addr = net.JoinHostPort(p.Upstream.Hostname(), "80")
	}
	c, err := p.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u := p.Upstream.User; u != nil {
		pw, _ := u.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT: %s", resp.Status)
	}
	return bufferedConn(c, br), nil
}

func (p *Proxy) serveMITM(raw net.Conn, host string) {
	tc := tls.Server(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(h.ServerName)
			if name == "" {
				name = host
			}
			if !p.Hosts[name] {
				return nil, fmt.Errorf("SNI %q not intercepted", name)
			}
			return p.CA.Leaf(name)
		},
	})
	if err := tc.Handshake(); err != nil {
		p.Logf("tls handshake with client for %s failed: %v", host, err)
		tc.Close()
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = host
			pr.Out.Host = host
		},
		Transport:     p.transport,
		FlushInterval: -1, // pass SSE through without buffering
		ErrorLog:      quiet,
		ModifyResponse: func(resp *http.Response) error {
			if note, ok := resp.Request.Context().Value(noteKey{}).(string); ok {
				p.Logf("%s %s -> %d", note, resp.Request.URL.Path, resp.StatusCode)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.Logf("upstream %s%s: %v", host, r.URL.Path, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	ln := newOneConnListener(tc)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && p.selected(r.URL.Path) {
				var err error
				if r, err = p.rewriteBody(r); err != nil {
					p.Logf("rewrite %s: %v (forwarding original)", r.URL.Path, err)
				}
			}
			rp.ServeHTTP(w, r)
		}),
		ErrorLog:    quiet,
		IdleTimeout: 5 * time.Minute,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				ln.Close()
			}
		},
	}
	srv.Serve(ln)
}

type noteKey struct{}

func (p *Proxy) selected(path string) bool {
	for _, s := range p.Paths {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	return false
}

// rewriteBody replaces r.Body. On error the original bytes are restored.
func (p *Proxy) rewriteBody(r *http.Request) (*http.Request, error) {
	src := r.Body
	orig, err := io.ReadAll(io.LimitReader(src, maxBody+1))
	restore := func() { // replay what was read, then whatever is left unread
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(orig), src), src}
	}
	if err != nil {
		restore()
		return r, err
	}
	if len(orig) > maxBody {
		restore()
		return r, errors.New("body too large")
	}
	body := orig
	gz := strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip")
	if gz {
		zr, err := gzip.NewReader(bytes.NewReader(orig))
		if err != nil {
			restore()
			return r, err
		}
		body, err = io.ReadAll(io.LimitReader(zr, maxBody))
		if err != nil {
			restore()
			return r, err
		}
	}
	out, note := p.Rewrite(r, body)
	if note == "" {
		restore()
		return r, nil
	}
	if gz {
		r.Header.Del("Content-Encoding")
	}
	src.Close()
	r.Body = io.NopCloser(bytes.NewReader(out))
	if r.ContentLength >= 0 { // otherwise stay chunked, as agy sent it
		r.ContentLength = int64(len(out))
	}
	return r.WithContext(context.WithValue(r.Context(), noteKey{}, note)), nil
}

// oneConnListener hands out a single connection, then blocks until closed.
type oneConnListener struct {
	mu   sync.Mutex
	c    net.Conn
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{c: c, done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.c
	l.c = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

type readConn struct {
	net.Conn
	r io.Reader
}

func (c *readConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *readConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func bufferedConn(c net.Conn, br *bufio.Reader) net.Conn {
	if br == nil || br.Buffered() == 0 {
		return c
	}
	return &readConn{Conn: c, r: io.MultiReader(io.LimitReader(br, int64(br.Buffered())), c)}
}
