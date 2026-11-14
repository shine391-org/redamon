package http

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// newProxyDialer returns an HTTP CONNECT dialer. The proxy URL is supplied by
// RedAmon's capture routing; it is never inferred from the environment, so an
// inherited proxy cannot silently take target traffic.
func newProxyDialer(proxyURL string, tls bool) (*proxyDialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	return &proxyDialer{u: u, tls: tls}, nil
}

type proxyDialer struct {
	u   *url.URL
	tls bool
	mu  sync.Mutex
}

func (d *proxyDialer) proxyAddr() string {
	host := d.u.Host
	if !strings.Contains(host, ":") {
		if d.u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host
}

func (d *proxyDialer) Dial(addr string) (net.Conn, error) {
	d.mu.Lock()
	proxyAddr := d.proxyAddr()
	d.mu.Unlock()
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	// A plain-HTTP target uses an ordinary forward-proxy request, so the proxy
	// can inspect and strip the context header. Only TLS targets need CONNECT.
	if !d.tls && !strings.HasSuffix(addr, ":443") {
		return conn, nil
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", addr, addr)
	if d.u.User != nil {
		req += "Proxy-Authorization: Basic " + d.u.User.String() + "\r\n"
	}
	if _, err := conn.Write([]byte(req + "\r\n")); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}
	line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	if !strings.Contains(line, " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", line)
	}
	if strings.HasPrefix(addr, "https:") || strings.HasSuffix(addr, ":443") {
		host := strings.TrimPrefix(addr, "https://")
		host = strings.TrimPrefix(host, "http://")
		host = strings.Split(host, ":")[0]
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	// A failed proxy dial returns above. Returning the tunnel for a plain HTTP
	// target is the correct CONNECT result; no direct fallback exists here.
	return conn, nil
}
