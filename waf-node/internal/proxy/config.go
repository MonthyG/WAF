package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	SiteID           string   `json:"site_id"`
	Hostname         string   `json:"hostname"`
	Origin           string   `json:"origin"`
	Origins          []Origin `json:"origins,omitempty"`
	Listen           string   `json:"listen"`
	ManagementListen string   `json:"management_listen"`
	Mode             string   `json:"mode"`
	ParanoiaLevel    int      `json:"paranoia_level"`
	RequestBodyLimit int64    `json:"request_body_limit"`
	InspectResponse  bool     `json:"inspect_response_body"`
}

type Origin struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

func LoadConfig(path string) (Config, error) {
	c := Config{SiteID: "local-site", Hostname: "shop.localhost", Origin: "http://127.0.0.1:9080", Listen: "127.0.0.1:8080", ManagementListen: "127.0.0.1:9090", Mode: "detect", ParanoiaLevel: 1, RequestBodyLimit: 1 << 20}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("config must contain exactly one JSON object")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if len(c.Origins) > 20 {
		return fmt.Errorf("maximum 20 origins")
	}
	for _, o := range c.Origins {
		other := c
		other.Origin = o.URL
		other.Origins = nil
		if err := other.Validate(); err != nil {
			return err
		}
		if o.Weight < 1 || o.Weight > 100 {
			return fmt.Errorf("origin weight must be 1–100")
		}
	}
	if c.SiteID == "" || len(c.SiteID) > 128 {
		return fmt.Errorf("site_id must be 1–128 characters")
	}
	if !validHostname(c.Hostname) {
		return fmt.Errorf("hostname must be a lowercase DNS hostname without port or wildcard")
	}
	u, err := url.Parse(c.Origin)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("origin must be an http(s) origin URL without credentials, path, query, or fragment")
	}
	if c.Mode != "detect" && c.Mode != "block" && c.Mode != "off" {
		return fmt.Errorf("invalid mode")
	}
	if c.ParanoiaLevel < 1 || c.ParanoiaLevel > 4 {
		return fmt.Errorf("paranoia_level must be 1–4")
	}
	if c.RequestBodyLimit < 1 || c.RequestBodyLimit > 128<<20 {
		return fmt.Errorf("invalid request_body_limit")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	host, _, err := net.SplitHostPort(c.ManagementListen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("management_listen must bind a literal loopback IP in this phase")
	}
	if c.Listen == c.ManagementListen {
		return fmt.Errorf("traffic and management listeners must differ")
	}
	return nil
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 || h != strings.ToLower(h) {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
