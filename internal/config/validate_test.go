package config

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 키를 정해진 값으로 만든다. 부를 때마다 같은 값이 나와야 두 설정을 견주는
// 시험이 성립한다.
func keyPair(t *testing.T, fill byte) (priv, pub string) {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// 어긋난 곳이 없는 설정을 만든다. 각 시험은 여기서 한 군데만 어긋뜨린다.
func good(t *testing.T) *Config {
	t.Helper()
	privA, pubA := keyPair(t, 1)
	_, pubB := keyPair(t, 2)
	key := filepath.Join(tempDir(t), "private.key")
	if err := os.WriteFile(key, []byte(privA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Config{
		Self: Self{
			PeerID: "srv-a", PrivateKey: key,
			TunnelCIDR: "10.91.0.0/24", ListenPort: 51820,
			Tun: Tun{Name: "cs0", MTU: 1420},
		},
		Peers: []Peer{
			{PeerID: "srv-a", PublicKey: pubA, TunnelIP: "10.91.0.1",
				Endpoints: []string{"10.0.5.1:51820"},
				Services:  []Service{{App: "billing", Port: 8080}}},
			{PeerID: "srv-b", PublicKey: pubB, TunnelIP: "10.91.0.2",
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

// TestIPv6접속주소는받는다는 터널 안과 밖의 경계를 못박는다. 터널 IP는 IPv4만
// 되지만 상대의 접속 주소는 IPv6도 된다. wg가 그 위에서 돌기 때문이다.
func TestIPv6접속주소는받는다(t *testing.T) {
	c := good(t)
	c.Peers[1].Endpoints = []string{"[2001:db8::2]:51820"}
	if p := c.Validate(); len(p) != 0 {
		t.Fatalf("IPv6 접속 주소를 거절했다: %v", p)
	}
}

// TestTunnelIP모드는실제IP없이도뜬다는 nat.incoming이 tunnel-ip이면 이 머신의
// 실제 IP를 몰라도 되는지 본다. 바꿀 주소가 필요 없기 때문이다.
func TestTunnelIP모드는실제IP없이도뜬다(t *testing.T) {
	c := good(t)
	c.Peers[0].Endpoints = []string{"[2001:db8::1]:51820"}
	c.Self.NAT.Incoming = "tunnel-ip"
	if p := c.Validate(); len(p) != 0 {
		t.Fatalf("tunnel-ip인데 실제 IP를 요구했다: %v", p)
	}
}

// TestRealIPs는 addresses가 없으면 endpoints의 IPv4를 실제 IP로 쓰는지 본다.
func TestRealIPs(t *testing.T) {
	p := Peer{Endpoints: []string{"10.0.5.2:51820", "[2001:db8::2]:51820", "10.0.5.2:51821", "10.0.9.2:51820"}}
	got := fmt.Sprint(p.RealIPs())
	if got != "[10.0.5.2 10.0.9.2]" {
		t.Fatalf("endpoints에서 IPv4만 한 번씩 골라야 하는데 %s", got)
	}
	p.Addresses = []string{"10.0.7.2", "이건 주소가 아니다"}
	if got := fmt.Sprint(p.RealIPs()); got != "[10.0.7.2]" {
		t.Fatalf("addresses가 있으면 그것만 써야 하는데 %s", got)
	}
}

// TestHashFiles는 설정 해시의 계산이 정한 모양 그대로인지 본다. 설정을 두는 쪽이
// 같은 계산을 하므로 모양이 바뀌면 그쪽이 csa의 답을 알아보지 못한다.
func TestHashFiles(t *testing.T) {
	csa, peers, policy := []byte("a = 1\n"), []byte("[[peer]]\n"), []byte("")
	sum := sha256.Sum256([]byte("csa.toml\n6\na = 1\npeers.toml\n9\n[[peer]]\npolicy.toml\n0\n"))
	want := hex.EncodeToString(sum[:])
	if got := HashFiles(csa, peers, policy); got != want {
		t.Fatalf("해시가 정한 모양과 다르다.\n얻음 %s\n기대 %s", got, want)
	}
	if HashFiles(csa, peers, []byte("x")) == want {
		t.Fatal("내용이 다른데 해시가 같다")
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
		{"공개키가 겹친다", func(c *Config) { c.Peers[1].PublicKey = c.Peers[0].PublicKey }, "같은 공개키"},
		{"적은 모양만 다른 같은 공개키", func(c *Config) { c.Peers[1].PublicKey = " " + c.Peers[0].PublicKey + " " }, "같은 공개키"},
		{"공개키가 base64가 아니다", func(c *Config) { c.Peers[1].PublicKey = "이건 base64가 아니다" }, "public-key를 읽을 수 없다"},
		{"공개키가 32바이트가 아니다", func(c *Config) { c.Peers[1].PublicKey = "aGVsbG8=" }, "32바이트"},
		{"터널 IP가 IPv6다", func(c *Config) { c.Peers[1].TunnelIP = "fd00::2" }, "IPv4여야 한다"},
		{"터널 대역이 IPv6다", func(c *Config) { c.Self.TunnelCIDR = "fd00::/64" }, "IPv4여야 한다"},
		{"addresses를 읽을 수 없다", func(c *Config) { c.Peers[1].Addresses = []string{"바보"} }, "addresses를 읽을 수 없다"},
		{"addresses가 IPv6다", func(c *Config) { c.Peers[1].Addresses = []string{"2001:db8::2"} }, "addresses는 IPv4"},
		{"addresses가 터널 대역 안이다", func(c *Config) { c.Peers[1].Addresses = []string{"10.91.0.9"} }, "tunnel-cidr 안"},
		{"실제 IP가 두 peer에 나타난다", func(c *Config) { c.Peers[1].Addresses = []string{"10.0.5.1"} }, "실제 IP가 두 peer"},
		{"endpoints의 IP가 다른 peer의 addresses와 같다", func(c *Config) {
			c.Peers[0].Addresses = []string{"10.0.5.2"}
		}, "실제 IP가 두 peer"},
		{"addresses가 없는데 endpoints의 IP가 터널 대역 안이다", func(c *Config) {
			c.Peers[1].Endpoints = []string{"10.91.0.9:51820"}
		}, "endpoints의 IP가 tunnel-cidr 안"},
		{"nat.outgoing이 모르는 값이다", func(c *Config) { c.Self.NAT.Outgoing = "돌려" }, "nat.outgoing은"},
		{"nat.incoming이 모르는 값이다", func(c *Config) { c.Self.NAT.Incoming = "보여" }, "nat.incoming은"},
		{"real-ip인데 이 머신의 실제 IP를 모른다", func(c *Config) {
			c.Peers[0].Endpoints = []string{"[2001:db8::1]:51820"}
		}, "실제 IP를 모른다"},
		{"peer-id에 대문자가 있다", func(c *Config) { c.Peers[1].PeerID = "Srv-B" }, "소문자와 숫자와 붙임표"},
		{"peer-id에 경로 글자가 있다", func(c *Config) { c.Peers[1].PeerID = "../etc/x" }, "소문자와 숫자와 붙임표"},
		{"peer-id에 점이 있다", func(c *Config) { c.Peers[1].PeerID = "srv.b" }, "소문자와 숫자와 붙임표"},
		{"app에 점이 있다", func(c *Config) { c.Peers[0].Services[0].App = "bill.ing" }, "소문자와 숫자와 붙임표"},
		{"tun.name이 너무 길다", func(c *Config) { c.Self.Tun.Name = "cs0123456789abcdef" }, "15글자를 넘는다"},
		{"tun.name에 슬래시가 있다", func(c *Config) { c.Self.Tun.Name = "cs/0" }, "쓸 수 없는 글자"},
		{"endpoint의 포트가 0이다", func(c *Config) { c.Peers[1].Endpoints = []string{"10.0.5.2:0"} }, "포트가 0"},
		{"공개키가 전부 0이다", func(c *Config) { c.Peers[1].PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }, "전부 0"},
		{"개인키를 다른 사용자가 읽을 수 있다", func(c *Config) {
			if err := os.Chmod(c.Self.PrivateKey, 0o644); err != nil {
				panic(err)
			}
		}, "다른 사용자가 읽을 수 있다"},
		{"개인키 자리가 디렉터리다", func(c *Config) { c.Self.PrivateKey = filepath.Dir(c.Self.PrivateKey) }, "일반 파일이 아니다"},
		{"개인키 자리가 심볼릭 링크다", func(c *Config) {
			link := c.Self.PrivateKey + ".link"
			if err := os.Symlink(c.Self.PrivateKey, link); err != nil {
				panic(err)
			}
			c.Self.PrivateKey = link
		}, "심볼릭 링크"},
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
		{"guard.mode가 모르는 값이다", func(c *Config) { c.Self.Guard.Mode = "닫아" }, "guard.mode는"},
		{"guard의 열어 둘 포트가 범위를 벗어났다", func(c *Config) {
			c.Self.Guard.Mode = "all"
			c.Self.Guard.KeepTCP = []int{70000}
		}, "열어 둘 포트가 범위"},
		{"열어 둘 포트를 쓰지 않는 모드에 적었다", func(c *Config) {
			c.Self.Guard.KeepTCP = []int{22}
		}, "all일 때만 쓴다"},
		{"한 peer 안에서 포트가 겹친다", func(c *Config) {
			c.Peers[0].Services = append(c.Peers[0].Services, Service{App: "admin", Port: 8080})
		}, "포트가 겹친다"},
		{"서비스 포트가 wg 포트와 같다", func(c *Config) {
			c.Peers[0].Services[0].Port = c.Self.ListenPort
		}, "listen-port와 같다"},
		{"개인키와 자기 공개키가 짝이 아니다", func(c *Config) {
			_, other := keyPair(t, 3)
			c.Peers[0].PublicKey = other
		}, "짝이 아니다"},
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

// TestLoad모르는열쇠를거절한다는 오타가 보안 설정을 조용히 뒤로 물리기
// 때문이다. [psk]의 mode를 modee로 잘못 적으면 mode가 빈 값이 되고, 빈 값은
// optional과 같다. 운영자는 키를 반드시 쓰게 했다고 여기는데 csa는 키 없이
// 기동한다.
func TestLoad모르는열쇠를거절한다(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"csa.toml의 오타", map[string]string{"csa.toml": "peer-id = \"srv-a\"\n\n[psk]\nmodee = \"required\"\n"}},
		{"0.1.x의 domain", map[string]string{"csa.toml": "peer-id = \"srv-a\"\ndomain = \"cs.example.internal\"\n"}},
		{"0.1.x의 [dns]", map[string]string{"csa.toml": "peer-id = \"srv-a\"\n\n[dns]\nlisten = \"127.0.53.1:53\"\n"}},
		{"peers.toml의 오타", map[string]string{"peers.toml": "[[peer]]\npeer-id = \"srv-a\"\npublik-key = \"x\"\n"}},
		{"policy.toml의 오타", map[string]string{"policy.toml": "outbond = [\"srv-b/api\"]\n"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := tempDir(t)
			for _, n := range []string{"csa.toml", "peers.toml", "policy.toml"} {
				body := c.files[n]
				if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Load(dir)
			if err == nil {
				t.Fatal("모르는 열쇠가 있는 설정을 받아들였다")
			}
			if !strings.Contains(err.Error(), "모르는 열쇠") {
				t.Fatalf("무엇이 잘못인지 알리지 않는다: %v", err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := tempDir(t)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("csa.toml", `
peer-id     = "srv-a"
private-key = "/etc/callsignet/private.key"
tunnel-cidr = "10.91.0.0/24"
listen-port = 51820

[tun]
name = "cs0"
mtu  = 1420

[nat]
outgoing = "services"
incoming = "tunnel-ip"
`)
	write("peers.toml", `
[[peer]]
peer-id    = "srv-a"
public-key = "AAAA"
tunnel-ip  = "10.91.0.1"
endpoints  = ["10.0.5.1:51820"]
addresses  = ["10.0.5.1", "10.0.9.1"]
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
	if c.Self.PeerID != "srv-a" || c.Self.Tun.MTU != 1420 || c.Self.NAT.Outgoing != "services" || c.Self.NAT.Incoming != "tunnel-ip" {
		t.Fatalf("csa.toml을 잘못 읽었다: %+v", c.Self)
	}
	if len(c.Peers) != 1 || c.Peers[0].Services[0].Port != 8080 || len(c.Peers[0].Addresses) != 2 {
		t.Fatalf("peers.toml을 잘못 읽었다: %+v", c.Peers)
	}
	if len(c.Policy.Outbound) != 1 || c.Policy.Inbound[0].App != "billing" {
		t.Fatalf("policy.toml을 잘못 읽었다: %+v", c.Policy)
	}
	if c.Find("srv-a") == nil || c.Find("없음") != nil {
		t.Fatal("Find가 잘못 찾는다")
	}
	// 해시는 읽은 파일의 바이트 그대로에서 나온다.
	var raw [3][]byte
	for i, n := range FileNames {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = b
	}
	if want := HashFiles(raw[0], raw[1], raw[2]); c.Hash != want {
		t.Fatalf("Load의 해시가 파일의 해시와 다르다. %s, 기대 %s", c.Hash, want)
	}
	// 파일이 바뀌면 다시 읽은 설정의 해시도 바뀐다.
	write("policy.toml", "outbound = []\n")
	c2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Hash == c.Hash {
		t.Fatal("policy.toml이 바뀌었는데 해시가 같다")
	}
}

// TestLoadPSK전부0인키를거절한다는 wg에서 전부 0인 사전 공유키가 키를 쓰지
// 않는 것과 같기 때문이다. 그런 파일을 받아들이면 psk.mode가 required인데도
// 키 없이 세션이 서고 csa status는 키를 쓴다고 말한다.
func TestLoadPSK전부0인키를거절한다(t *testing.T) {
	dir := tempDir(t)
	c := &Config{
		Self:  Self{PeerID: "srv-a", PSK: PSK{Dir: dir, Mode: "required"}},
		Peers: []Peer{{PeerID: "srv-b"}},
	}
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(filepath.Join(dir, "srv-b.key"), []byte(zero+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.LoadPSK("srv-b"); err == nil {
		t.Fatal("전부 0인 사전 공유키를 받아들였다")
	}

	good := make([]byte, 32)
	good[0] = 1
	if err := os.WriteFile(filepath.Join(dir, "srv-b.key"),
		[]byte(base64.StdEncoding.EncodeToString(good)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.LoadPSK("srv-b"); err != nil || !ok {
		t.Fatalf("바른 키를 거절했다: %v", err)
	}
}
