package http

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRedamonAuthority(t *testing.T) {
	for _, row := range [][2]string{{"target.test", "target.test:443"}, {"target.test:8443", "target.test:8443"}, {"[::1]", "[::1]:443"}, {"::1", "[::1]:443"}, {"[::1]:8443", "[::1]:8443"}} {
		got, err := normalizeAuthority(row[0], 443)
		if err != nil || got != row[1] {
			t.Fatalf("%q got %q err %v", row[0], got, err)
		}
	}
	for _, bad := range []string{"", "target:0", "target:99999", "a\r\nInjected: yes", "bad:port"} {
		if _, err := normalizeAuthority(bad, 443); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
func TestRedamonProxyValidation(t *testing.T) {
	for _, bad := range []string{"socks5://127.0.0.1:8888", "https://localhost:8888", "localhost:8888", "http://", "http://localhost:0", "http://localhost:99999", "http://user:pass@localhost", "http://localhost/path", "http://localhost?secret=x"} {
		if ValidateProxyURL(bad) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, good := range []string{"", "http://localhost", "http://127.0.0.1:8888", "http://[::1]:8888"} {
		if err := ValidateProxyURL(good); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRedamonFragmentedConnectAndReadAhead(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	d, _ := newProxyDialer("http://localhost:8888")
	go func() {
		defer proxy.Close()
		br := bufio.NewReader(proxy)
		for {
			s, _ := br.ReadString('\n')
			if s == "\r\n" {
				break
			}
		}
		io.WriteString(proxy, "HTTP/1.1 ")
		time.Sleep(10 * time.Millisecond)
		io.WriteString(proxy, "200 OK\r\nX-Proxy: yes\r\n\r\nNEXT")
	}()
	br, err := d.connect(client, "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err := io.ReadFull(br, data); err != nil || string(data) != "NEXT" {
		t.Fatalf("read-ahead lost %q %v", data, err)
	}
}
func TestRedamonAggregateHeaderLimit(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	d, _ := newProxyDialer("http://localhost:8888")
	go func() {
		defer proxy.Close()
		br := bufio.NewReader(proxy)
		for {
			s, _ := br.ReadString('\n')
			if s == "\r\n" {
				break
			}
		}
		io.WriteString(proxy, "HTTP/1.1 200 OK\r\n"+strings.Repeat("X: "+strings.Repeat("a", 1000)+"\r\n", 70)+"\r\n")
	}()
	if _, err := d.connect(client, "target.test:443"); err == nil {
		t.Fatal("accepted oversized aggregate headers")
	}
}
