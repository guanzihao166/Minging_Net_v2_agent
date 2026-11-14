package wire

import (
	"encoding/json"
	"time"
)

const ProtocolVersion = 1

type Credential struct {
	UUID       string `json:"uuid,omitempty"`
	Password   string `json:"password,omitempty"`
	SSKey      string `json:"ss_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	Address    string `json:"address,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
}
type ClientConfig struct {
	TLS              bool     `json:"tls"`
	ServerName       string   `json:"server_name"`
	ALPN             []string `json:"alpn"`
	Transport        string   `json:"transport"`
	Path             string   `json:"path"`
	Host             string   `json:"host"`
	ServiceName      string   `json:"service_name"`
	Flow             string   `json:"flow"`
	RealityPublicKey string   `json:"reality_public_key"`
	RealityShortID   string   `json:"reality_short_id"`
	Method           string   `json:"method"`
	ServerKey        string   `json:"server_key"`
	WGPublicKey      string   `json:"wg_public_key"`
	MTU              int      `json:"mtu"`
	ObfsPassword     string   `json:"obfs_password"`
	Congestion       string   `json:"congestion"`
	// Fields below require agent 0.2.0; the controller withholds inbounds that
	// use them from older agents rather than letting them be misread.
	Security             string          `json:"security,omitempty"` // none, tls or reality; empty follows TLS
	Fingerprint          string          `json:"fingerprint,omitempty"`
	RealityTarget        string          `json:"reality_target,omitempty"`
	RealityServerNames   []string        `json:"reality_server_names,omitempty"`
	RealitySpiderX       string          `json:"reality_spider_x,omitempty"`
	RealityMldsa65Verify string          `json:"reality_mldsa65_verify,omitempty"`
	RealityMaxTimeDiff   int64           `json:"reality_max_time_diff,omitempty"` // milliseconds
	XHTTPMode            string          `json:"xhttp_mode,omitempty"`
	XHTTPExtra           json.RawMessage `json:"xhttp_extra,omitempty"`
	GRPCMultiMode        bool            `json:"grpc_multi_mode,omitempty"`
	Encryption           string          `json:"encryption,omitempty"` // VLESS client "encryption"
	VMessCipher          string          `json:"vmess_cipher,omitempty"`
	TLSMinVersion        string          `json:"tls_min_version,omitempty"`
	RejectUnknownSNI     bool            `json:"reject_unknown_sni,omitempty"`
	Masquerade           string          `json:"masquerade,omitempty"`
	PaddingScheme        []string        `json:"padding_scheme,omitempty"`
	// RealityRejectFallback closes connections that fail REALITY
	// authentication instead of relaying them to the target (agent 0.3.0).
	RealityRejectFallback bool `json:"reality_reject_fallback,omitempty"`
}

// EffectiveSecurity maps the legacy TLS flag onto the security layer name.
func (c ClientConfig) EffectiveSecurity() string {
	if c.Security != "" {
		return c.Security
	}
	if c.TLS {
		return "tls"
	}
	return "none"
}

type Secrets struct {
	LocalTLS     bool   `json:"local_tls,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
	PrivateKey   string `json:"private_key,omitempty"`
	WGPrivateKey string `json:"wg_private_key,omitempty"`
	// REALITY X25519 private key and optional ML-DSA-65 seed (base64url, raw).
	RealityPrivateKey  string `json:"reality_private_key,omitempty"`
	RealityMldsa65Seed string `json:"reality_mldsa65_seed,omitempty"`
	// VLESS Encryption server "decryption" string; it embeds the private key.
	Decryption string `json:"decryption,omitempty"`
}
type User struct {
	ID             int64      `json:"id"`
	Epoch          int64      `json:"epoch"`
	ExpiresAt      time.Time  `json:"expires_at"`
	SpeedMbps      int        `json:"speed_mbps"`
	MaxConnections int        `json:"max_connections"`
	Credential     Credential `json:"credential"`
}
type Inbound struct {
	ID         int64        `json:"id"`
	Protocol   string       `json:"protocol"`
	ListenHost string       `json:"listen_host"`
	Port       int          `json:"port"`
	Config     ClientConfig `json:"config"`
	Secrets    Secrets      `json:"secrets"`
	Users      []User       `json:"users"`
}
type Snapshot struct {
	ProtocolVersion int       `json:"protocol_version"`
	ServerID        int64     `json:"server_id"`
	Revision        string    `json:"revision"`
	IssuedAt        time.Time `json:"issued_at"`
	ValidUntil      time.Time `json:"valid_until"`
	Inbounds        []Inbound `json:"inbounds"`
}
type Lease struct {
	ID        string `json:"id"`
	UserID    int64  `json:"user_id"`
	InboundID int64  `json:"inbound_id"`
	Epoch     int64  `json:"epoch"`
	Close     bool   `json:"close"`
}
type LeaseResult struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}
type GrantRequest struct {
	ID        string `json:"id"`
	LeaseID   string `json:"lease_id"`
	UserID    int64  `json:"user_id"`
	InboundID int64  `json:"inbound_id"`
	Epoch     int64  `json:"epoch"`
	Bytes     int64  `json:"bytes"`
}
type Grant struct {
	ID        string    `json:"id"`
	Bytes     int64     `json:"bytes"`
	ExpiresAt time.Time `json:"expires_at"`
	Closed    bool      `json:"closed,omitempty"`
}
type GrantReport struct {
	ID       string `json:"id"`
	Upload   int64  `json:"upload_bytes"`
	Download int64  `json:"download_bytes"`
	Closed   bool   `json:"closed"`
}
type Metrics struct {
	UploadBPS     int64   `json:"upload_bps"`
	DownloadBPS   int64   `json:"download_bps"`
	Connections   int     `json:"connections"`
	CPU           float64 `json:"cpu_percent"`
	Memory        int64   `json:"memory_bytes"`
	MemoryTotal   int64   `json:"memory_total_bytes"`
	Uptime        int64   `json:"uptime_seconds"`
	TotalUpload   int64   `json:"total_upload_bytes"`
	TotalDownload int64   `json:"total_download_bytes"`
}
type UserConnections struct {
	UserID int64 `json:"user_id"`
	Count  int   `json:"count"`
}
type Report struct {
	ID          string            `json:"report_id"`
	At          time.Time         `json:"at"`
	Revision    string            `json:"revision"`
	Healthy     bool              `json:"healthy"`
	Error       string            `json:"error"`
	Version     string            `json:"version"`
	Metrics     Metrics           `json:"metrics"`
	Grants      []GrantReport     `json:"grants"`
	Connections []UserConnections `json:"connections"`
}
