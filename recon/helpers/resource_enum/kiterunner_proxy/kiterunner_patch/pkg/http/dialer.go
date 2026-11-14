package http

// RedAmon capture-proxy transport for Kiterunner.
//
// The stock binary has no dialer hook, so this file (copied into pkg/http by
// build.py) provides one. It never dials the target directly: every connection
// goes to the configured capture proxy. A plaintext target is written as an
// origin-form request on the proxy connection (the proxy parses it and strips
// X-Redamon-Ctx before forwarding); a TLS target gets an HTTP CONNECT tunnel
// and the raw tunnel is handed back so fasthttp itself performs the target TLS
// handshake. Target TLS is therefore owned by fasthttp, not by this file.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

const (
	// proxyDialTimeout bounds each phase of the proxy handshake. It is
	// deliberately independent of the scan's per-request timeout because the
	// dial function receives no timeout from fasthttp.
	proxyDialTimeout = 20 * time.Second
	// proxyHeaderLimit bounds the CONNECT response header block. Real proxies
	// answer in one small segment; anything larger is malformed or hostile.
	proxyHeaderLimit = 64 * 1024
)

// newProxyDialer validates the capture proxy URL. Only plain HTTP proxies are
// supported: a TLS-to-proxy listener would need its own trust anchor, which
// this build does not carry, so https is rejected explicitly rather than being
// dialled in the clear.
func newProxyDialer(proxyURL string) (*proxyDialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported proxy scheme %q (only http is supported)", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid proxy URL: missing host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("proxy credentials, paths, queries and fragments are not supported")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid proxy port")
		}
	}
	return &proxyDialer{u: u}, nil
}

// ValidateProxyURL reports whether proxyURL can be used. An empty value means
// no proxy is configured and is valid; a non-empty value must parse as an
// http:// URL with a host, because anything else cannot carry capture traffic.
func ValidateProxyURL(proxyURL string) error {
	if proxyURL == "" {
		return nil
	}
	_, err := newProxyDialer(proxyURL)
	return err
}

type proxyDialer struct {
	u *url.URL
}

// proxyAddr returns the proxy TCP address, adding the default HTTP port when
// the URL omitted one. IPv6 literals keep their brackets via JoinHostPort.
func (d *proxyDialer) proxyAddr() string {
	host := d.u.Host
	if d.u.Port() == "" {
		return net.JoinHostPort(d.u.Hostname(), "80")
	}
	return host
}

func (d *proxyDialer) dialProxy() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", d.proxyAddr(), proxyDialTimeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// DialForward is the dial function for plaintext targets. It returns the raw
// proxy connection; fasthttp writes an origin-form request that the capture
// proxy parses (so it sees, and can strip, the context header).
func (d *proxyDialer) DialForward(addr string) (net.Conn, error) {
	return d.dialProxy()
}

// DialConnect is the dial function for TLS targets. It establishes a CONNECT
// tunnel to the target authority and returns the raw tunnel connection; the
// caller (fasthttp) performs the target TLS handshake over it.
func (d *proxyDialer) DialConnect(addr string) (net.Conn, error) {
	conn, err := d.dialProxy()
	if err != nil {
		return nil, err
	}
	authority, err := normalizeAuthority(addr, 443)
	if err != nil {
		conn.Close()
		return nil, err
	}
	br, err := d.connect(conn, authority)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Clear the handshake deadline: fasthttp manages the request lifecycle.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

// connect sends CONNECT and reads the full response header block. Any bytes
// read past the blank line belong to the tunnelled protocol and are preserved
// in the returned bufio.Reader (a TLS ServerHello can arrive immediately after
// the CONNECT response).
func (d *proxyDialer) connect(conn net.Conn, authority string) (*bufio.Reader, error) {
	var req strings.Builder
	req.WriteString("CONNECT ")
	req.WriteString(authority)
	req.WriteString(" HTTP/1.1\r\nHost: ")
	req.WriteString(authority)
	req.WriteString("\r\nProxy-Connection: Keep-Alive\r\n\r\n")

	if err := conn.SetDeadline(time.Now().Add(proxyDialTimeout)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, req.String()); err != nil {
		return nil, err
	}

	br := bufio.NewReaderSize(conn, 4096)
	statusLine, err := readHeaderLine(br)
	if err != nil {
		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}
	code, err := parseStatusLine(statusLine)
	if err != nil {
		return nil, fmt.Errorf("malformed CONNECT response %q", statusLine)
	}
	if code != 200 {
		return nil, fmt.Errorf("proxy CONNECT failed: %d %s", code, statusLine)
	}
	total := len(statusLine) + 2
	for {
		line, err := readHeaderLine(br)
		if err != nil {
			return nil, fmt.Errorf("reading CONNECT response headers: %w", err)
		}
		total += len(line) + 2
		if total > proxyHeaderLimit {
			return nil, fmt.Errorf("CONNECT headers too large")
		}
		if line == "" {
			break
		}
	}
	return br, nil
}

// readHeaderLine reads one CRLF-terminated header line, bounded by
// proxyHeaderLimit. Fragmented writes across segments are handled by
// ReadSlice blocking until the delimiter arrives.
func readHeaderLine(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := br.ReadSlice('\n')
		sb.Write(chunk)
		if sb.Len() > proxyHeaderLimit {
			return "", fmt.Errorf("CONNECT response header exceeds %d bytes", proxyHeaderLimit)
		}
		if err == nil {
			return strings.TrimRight(sb.String(), "\r\n"), nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return "", fmt.Errorf("incomplete CONNECT response header")
		}
		return "", err
	}
}

func parseStatusLine(line string) (int, error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, fmt.Errorf("malformed status line %q", line)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("malformed status code in %q", line)
	}
	return code, nil
}

// normalizeAuthority appends the default port when addr has none. This is the
// fix for default-port HTTPS targets: Kiterunner's Target.Host() omits :443,
// and fasthttp only calls addMissingPort when Dial == nil.
func normalizeAuthority(addr string, defaultPort int) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("empty target address")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
		if strings.ContainsAny(host, " /\r\n	") || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
			return "", fmt.Errorf("invalid target authority")
		}
		return net.JoinHostPort(host, strconv.Itoa(defaultPort)), nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || host == "" {
		return "", fmt.Errorf("invalid target authority")
	}
	return net.JoinHostPort(host, port), nil
}

// bufferedConn preserves bytes that were read ahead past the CONNECT response.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// failProxyDial is installed whenever a --proxy value is invalid. A non-nil
// dial function guarantees the client can never fall back to a direct
// connection, so X-Redamon-Ctx is never sent to a target outside capture.
func failProxyDial(err error) fasthttp.DialFunc {
	return func(string) (net.Conn, error) { return nil, err }
}

// proxyDialFunc builds the dial function for a client whose targets are TLS
// when tls is true and plaintext otherwise. When no proxy is configured it
// returns nil, preserving upstream's direct-dial behaviour (the wrapper only
// adds X-Redamon-Ctx together with --proxy, so a direct client is untagged).
func proxyDialFunc(tls bool) fasthttp.DialFunc {
	if proxyURL == "" {
		return nil
	}
	d, err := newProxyDialer(proxyURL)
	if err != nil {
		return failProxyDial(err)
	}
	if tls {
		return d.DialConnect
	}
	return d.DialForward
}
