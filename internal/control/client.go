package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServerID       int64    `json:"server_id"`
	Controller     string   `json:"controller"`
	Token          string   `json:"token"`
	Listen         string   `json:"listen"`
	ControllerIPs  []string `json:"controller_ips"`
	StateDirectory string   `json:"state_directory"`
	TLSDirectory   string   `json:"tls_directory"`
}

func (c *Config) Validate() error {
	u, e := url.Parse(c.Controller)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c.ServerID < 1 || len(c.Token) != 256 || len(c.ControllerIPs) == 0 {
		return errors.New("invalid controller configuration")
	}
	for _, r := range c.Token {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return errors.New("invalid agent token")
		}
	}
	for _, v := range c.ControllerIPs {
		if _, e := netip.ParsePrefix(v); e != nil {
			return errors.New("invalid controller IP allowlist")
		}
	}
	if c.Listen == "" {
		c.Listen = ":24442"
	}
	if c.StateDirectory == "" {
		c.StateDirectory = "/var/lib/minging-agent"
	}
	if c.TLSDirectory == "" {
		c.TLSDirectory = "/etc/minging-agent/tls"
	}
	_, port, err := net.SplitHostPort(c.Listen)
	n, parseErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || n < 1024 || n > 65535 {
		return errors.New("management listener requires an unprivileged TCP port")
	}
	if !filepath.IsAbs(c.StateDirectory) || !filepath.IsAbs(c.TLSDirectory) {
		return errors.New("agent directories must be absolute")
	}
	return nil
}

type Client struct {
	Config Config
	HTTP   *http.Client
}
type Error struct {
	Status int
	Wait   time.Duration
}

func (e Error) Error() string { return fmt.Sprintf("controller rejected request (HTTP %d)", e.Status) }
func New(c Config) (*Client, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	prefixes := []netip.Prefix{}
	for _, p := range c.ControllerIPs {
		x, _ := netip.ParsePrefix(p)
		prefixes = append(prefixes, x)
	}
	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 32, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			allowed := false
			for _, p := range prefixes {
				if p.Contains(ip.Unmap()) {
					allowed = true
				}
			}
			if allowed {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
			}
		}
		return nil, errors.New("controller address is outside the configured allowlist")
	}}
	return &Client{Config: c, HTTP: &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func (c *Client) Do(ctx context.Context, method, path string, input, output any) error {
	var raw []byte
	var e error
	if input != nil {
		raw, e = json.Marshal(input)
		if e != nil {
			return e
		}
	}
	return c.DoRaw(ctx, method, path, raw, output)
}
func (c *Client) DoRaw(ctx context.Context, method, path string, raw []byte, output any) error {
	req, e := http.NewRequestWithContext(ctx, method, c.Config.Controller+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	nonce, e := RandomID()
	if e != nil {
		return e
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Mnet-Server", fmt.Sprint(c.Config.ServerID))
	req.Header.Set("X-Mnet-Time", stamp)
	req.Header.Set("X-Mnet-Nonce", nonce)
	req.Header.Set("X-Mnet-Signature", wire.Signature(c.Config.Token, method, path, stamp, nonce, raw))
	res, e := c.HTTP.Do(req)
	if e != nil {
		return errors.New("controller connection failed")
	}
	defer res.Body.Close()
	body, e := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if e != nil {
		return e
	}
	if res.StatusCode != 200 {
		var problem struct {
			Wait int `json:"retry_after_ms"`
		}
		json.Unmarshal(body, &problem)
		return Error{res.StatusCode, time.Duration(max(20, min(2000, problem.Wait))) * time.Millisecond}
	}
	if output != nil {
		if e = json.Unmarshal(body, output); e != nil {
			return errors.New("invalid controller response")
		}
	}
	return nil
}
func (c *Client) Lease(ctx context.Context, x wire.Lease) (wire.LeaseResult, error) {
	var out wire.LeaseResult
	e := c.Do(ctx, "POST", "/api/agent/leases", x, &out)
	return out, e
}
func (c *Client) Grant(ctx context.Context, x wire.GrantRequest) (wire.Grant, error) {
	var out wire.Grant
	e := c.Do(ctx, "POST", "/api/agent/grants", x, &out)
	return out, e
}
func (c *Client) GrantStatus(ctx context.Context, id string) (wire.Grant, error) {
	var out wire.Grant
	if len(id) != 32 || strings.ContainsAny(id, "/?.") {
		return out, errors.New("invalid grant id")
	}
	e := c.Do(ctx, "GET", "/api/agent/grants/"+id, nil, &out)
	return out, e
}
