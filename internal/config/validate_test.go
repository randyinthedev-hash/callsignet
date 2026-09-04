package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 어긋난 곳이 없는 설정을 만든다. 각 시험은 여기서 한 군데만 어긋뜨린다.
func good(t *testing.T) *Config {
	t.Helper()
	key := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(key, []byte("Zm9v\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Config{
		Self: Self{
			PeerID: "srv-a", PrivateKey: key, Domain: "cs.example.internal",
			TunnelCIDR: "10.91.0.0/24", ListenPort: 51820,
			Tun: Tun{Name: "cs0", MTU: 1420},
			DNS: DNS{Listen: "127.0.0.54:53", TTL: 300},
		},
		Peers: []Peer{
			{PeerID: "srv-a", PublicKey: "AAAA", TunnelIP: "10.91.0.1",
				Endpoints: []string{"10.0.5.1:51820"},
				Services:  []Service{{App: "billing", Port: 8080}}},
			{PeerID: "srv-b", PublicKey: "BBBB", TunnelIP: "10.91.0.2",
				Endpoints: []string{"10.0.5.2:51820"},
				Services:  []Service{{App: "report", Port: 8080}}},
		},
		Policy: Policy{
			Inbound:  []Inbound{{App: "billing", Allow: []string{"srv-b"}}},
			Outbound: []string{"srv-b/report"},
		},
	}
}

func TestGoodConfigHasNoProblem(t *testing.T) {
	if p := good(t).Validate(); len(p) != 0 {
		t.Fatalf("어긋난 곳이 없어야 하는데 %v", p)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		bend func(*Config)
		want string
	}{
		{"자기 peer-id가 목록에 없다", func(c *Config) { c.Self.PeerID = "srv-x" }, "peers.toml에 없다"},
		{"터널 IP가 겹친다", func(c *Config) { c.Peers[1].TunnelIP = "10.91.0.1" }, "겹친다"},
		{"터널 IP가 대역 밖이다", func(c *Config) { c.Peers[1].TunnelIP = "10.92.0.2" }, "밖이다"},
		{"공개키가 겹친다", func(c *Config) { c.Peers[1].PublicKey = "AAAA" }, "같은 공개키"},
		{"peer-id가 두 번 나온다", func(c *Config) { c.Peers[1].PeerID = "srv-a" }, "두 번 나온다"},
		{"개인키 파일이 없다", func(c *Config) { c.Self.PrivateKey = "/없는/경로" }, "개인키 파일"},
		{"접속 주소를 읽을 수 없다", func(c *Config) { c.Peers[1].Endpoints = []string{"바보"} }, "endpoint"},
		{"정책이 없는 peer를 가리킨다", func(c *Config) { c.Policy.Outbound = []string{"srv-z/report"} }, "peers.toml에 없다"},
		{"정책이 없는 app을 가리킨다", func(c *Config) { c.Policy.Outbound = []string{"srv-b/없음"} }, "peer에 app이 없다"},
		{"outbound 형태가 틀렸다", func(c *Config) { c.Policy.Outbound = []string{"srv-b"} }, "peer-id/app 형태"},
		{"inbound가 없는 app을 가리킨다", func(c *Config) { c.Policy.Inbound[0].App = "없음" }, "이 머신의 서비스에 없다"},
		{"allow-cidr에 만료가 없다", func(c *Config) {
			c.Policy.Inbound[0].AllowCIDR = []string{"10.0.5.0/24"}
		}, "expires가 없다"},
		{"allow-cidr가 이미 만료됐다", func(c *Config) {
			c.Policy.Inbound[0].AllowCIDR = []string{"10.0.5.0/24"}
			c.Policy.Inbound[0].Expires = "2020-01-01"
		}, "만료됐다"},
		{"포트가 범위를 벗어났다", func(c *Config) { c.Peers[0].Services[0].Port = 70000 }, "port가 범위"},
		{"MTU가 범위를 벗어났다", func(c *Config) { c.Self.Tun.MTU = 9000 }, "mtu가 범위"},
		{"dns.listen이 없다", func(c *Config) { c.Self.DNS.Listen = "" }, "dns.listen이 없다"},
		{"dns.listen을 읽을 수 없다", func(c *Config) { c.Self.DNS.Listen = "포트없음" }, "dns.listen을 읽을 수 없다"},
		{"guard.mode가 모르는 값이다", func(c *Config) { c.Self.Guard.Mode = "닫아" }, "guard.mode는"},
		{"guard의 열어 둘 포트가 범위를 벗어났다", func(c *Config) {
			c.Self.Guard.Mode = "all"
			c.Self.Guard.KeepTCP = []int{70000}
		}, "열어 둘 포트가 범위"},
		{"열어 둘 포트를 쓰지 않는 모드에 적었다", func(c *Config) {
			c.Self.Guard.KeepTCP = []int{22}
		}, "all일 때만 쓴다"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good(t)
			tc.bend(c)
			got := c.Validate()
			for _, p := range got {
				if strings.Contains(p, tc.want) {
					return
				}
			}
			t.Fatalf("%q를 담은 문제를 찾지 못했다. 나온 것: %v", tc.want, got)
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("csa.toml", `
peer-id     = "srv-a"
private-key = "/etc/callsignet/private.key"
domain      = "cs.example.internal"
tunnel-cidr = "10.91.0.0/24"
listen-port = 51820

[tun]
name = "cs0"
mtu  = 1420

[dns]
listen = "127.0.0.54:53"
ttl    = 300
`)
	write("peers.toml", `
[[peer]]
peer-id    = "srv-a"
public-key = "AAAA"
tunnel-ip  = "10.91.0.1"
endpoints  = ["10.0.5.1:51820"]
services   = [{ app = "billing", port = 8080 }]
`)
	write("policy.toml", `
outbound = ["srv-a/billing"]

[[inbound]]
app   = "billing"
allow = ["srv-a"]
`)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Self.PeerID != "srv-a" || c.Self.Tun.MTU != 1420 || c.Self.DNS.Listen != "127.0.0.54:53" || c.Self.DNS.TTL != 300 {
		t.Fatalf("csa.toml을 잘못 읽었다: %+v", c.Self)
	}
	if len(c.Peers) != 1 || c.Peers[0].Services[0].Port != 8080 {
		t.Fatalf("peers.toml을 잘못 읽었다: %+v", c.Peers)
	}
	if len(c.Policy.Outbound) != 1 || c.Policy.Inbound[0].App != "billing" {
		t.Fatalf("policy.toml을 잘못 읽었다: %+v", c.Policy)
	}
	if c.Find("srv-a") == nil || c.Find("없음") != nil {
		t.Fatal("Find가 잘못 찾는다")
	}
}
