// Package config는 csa가 읽는 설정 파일을 다룬다.
//
// 설정은 /etc/callsignet/ 아래에 셋으로 나뉜다. csa.toml은 이 머신 자신에 대한
// 값이고, peers.toml은 모든 peer의 이름과 키와 주소와 서비스이며, policy.toml은
// 이 머신의 정책이다.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Self는 csa.toml이 담는 값이다.
type Self struct {
	PeerID     string `toml:"peer-id"`
	PrivateKey string `toml:"private-key"`
	Domain     string `toml:"domain"`
	TunnelCIDR string `toml:"tunnel-cidr"`
	ListenPort int    `toml:"listen-port"`
	Tun        Tun    `toml:"tun"`
	DNS        DNS    `toml:"dns"`
	Guard      Guard  `toml:"guard"`
	PSK        PSK    `toml:"psk"`
}

// PSK는 사전 공유키를 어디서 읽고 반드시 있어야 하는지를 정한다.
//
// wg는 상대마다 사전 공유키를 하나 받아 handshake에 섞는다. Curve25519가 뒷날
// 깨져도 그 키가 새지 않았으면 지난 세션의 비밀이 지켜진다. 지금 모아 두었다가
// 뒷날 푸는 공격에 대비하는 것이다.
//
// 키를 peers.toml에 적지 않고 디렉터리에 둔다. 파일 이름이 상대의 peer-id다.
// 키는 짝마다 하나인데 peers.toml은 모든 머신에서 같은 파일이므로, 거기 적으면
// 같은 항목이 머신마다 다른 짝을 가리키게 된다.
type PSK struct {
	Dir  string `toml:"dir"`
	Mode string `toml:"mode"`
}

// Guard는 직통 경로를 어디까지 닫을지 정한다.
//
// mode가 services면 csa는 peers.toml에 적힌 이 머신의 서비스 포트만 닫는다.
// all이면 아래 두 목록에 적은 포트 말고 모두 닫는다. off면 닫지 않는다.
// 비워 두면 services다.
type Guard struct {
	Mode    string `toml:"mode"`
	KeepTCP []int  `toml:"keep-tcp"`
	KeepUDP []int  `toml:"keep-udp"`
}

type Tun struct {
	Name string `toml:"name"`
	MTU  int    `toml:"mtu"`
}

// DefaultTunName은 csa.toml에 tun.name이 없을 때 쓰는 이름이다.
const DefaultTunName = "cs0"

// DefaultTunMTU는 csa.toml에 tun.mtu가 없을 때 쓰는 값이다. 바깥 인터페이스의
// MTU가 1500이면 wg가 덧붙이는 60바이트를 더해도 들어간다.
const DefaultTunMTU = 1420

// TunName은 csa가 만들 인터페이스의 이름이다.
func (s Self) TunName() string {
	if s.Tun.Name == "" {
		return DefaultTunName
	}
	return s.Tun.Name
}

// TunMTU는 csa가 만들 인터페이스의 MTU다.
func (s Self) TunMTU() int {
	if s.Tun.MTU == 0 {
		return DefaultTunMTU
	}
	return s.Tun.MTU
}

type DNS struct {
	Listen string `toml:"listen"`
	TTL    int    `toml:"ttl"`
}

// Service는 어느 peer에서 도는 앱 하나다.
type Service struct {
	App  string `toml:"app"`
	Port int    `toml:"port"`
}

// Peer는 peers.toml의 항목 하나다. 이 머신 자신도 여기 들어 있다.
type Peer struct {
	PeerID    string    `toml:"peer-id"`
	PublicKey string    `toml:"public-key"`
	TunnelIP  string    `toml:"tunnel-ip"`
	Endpoints []string  `toml:"endpoints"`
	Services  []Service `toml:"services"`
}

type peersFile struct {
	Peer []Peer `toml:"peer"`
}

// Inbound는 이 머신에 붙어도 되는 상대를 적은 규칙 하나다.
type Inbound struct {
	App       string   `toml:"app"`
	Allow     []string `toml:"allow"`
	AllowCIDR []string `toml:"allow-cidr"`
	Expires   string   `toml:"expires"`
}

// Policy는 policy.toml이 담는 값이다.
type Policy struct {
	Inbound  []Inbound `toml:"inbound"`
	Outbound []string  `toml:"outbound"`
}

// Config는 세 파일을 읽어 합친 것이다.
type Config struct {
	Self   Self
	Peers  []Peer
	Policy Policy
}

// Load는 디렉터리에서 세 파일을 읽는다. 검사하지는 않는다.
func Load(dir string) (*Config, error) {
	var c Config
	if err := decode(filepath.Join(dir, "csa.toml"), &c.Self); err != nil {
		return nil, err
	}
	var pf peersFile
	if err := decode(filepath.Join(dir, "peers.toml"), &pf); err != nil {
		return nil, err
	}
	c.Peers = pf.Peer
	if err := decode(filepath.Join(dir, "policy.toml"), &c.Policy); err != nil {
		return nil, err
	}
	return &c, nil
}

// decode는 파일 하나를 읽고 모르는 열쇠가 있으면 거절한다.
//
// 모르는 열쇠를 조용히 버리면 보안 설정이 소리 없이 뒤로 물러난다. `[psk]`의
// `mode`를 `modee`로 잘못 적으면 mode가 빈 값이 되고, 빈 값은 optional과 같다.
// 운영자는 사전 공유키를 반드시 쓰게 했다고 여기는데 csa는 키 없이 기동한다.
func decode(path string, v any) error {
	md, err := toml.DecodeFile(path, v)
	if err != nil {
		return fmt.Errorf("%s을 읽지 못했다: %w", filepath.Base(path), err)
	}
	if left := md.Undecoded(); len(left) > 0 {
		names := make([]string, 0, len(left))
		for _, k := range left {
			names = append(names, k.String())
		}
		return fmt.Errorf("%s에 모르는 열쇠가 있다. 오타인지 보라: %s",
			filepath.Base(path), strings.Join(names, ", "))
	}
	return nil
}

// PSKPath는 그 상대와 쓰는 사전 공유키 파일의 자리다. 디렉터리를 적지 않았으면
// 빈 문자열을 돌려준다.
func (c *Config) PSKPath(peerID string) string {
	if c.Self.PSK.Dir == "" || peerID == c.Self.PeerID {
		return ""
	}
	return filepath.Join(c.Self.PSK.Dir, peerID+".key")
}

// LoadPSK는 그 상대와 쓰는 사전 공유키를 읽는다. 파일이 없으면 두 번째 값이
// 거짓이다. 없는 것 자체는 잘못이 아니다. 반드시 있어야 하는지는 psk.mode가 정한다.
func (c *Config) LoadPSK(peerID string) (string, bool, error) {
	path := c.PSKPath(peerID)
	if path == "" {
		return "", false, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("사전 공유키를 읽지 못했다: %s: %w", path, err)
	}
	key := strings.TrimSpace(string(b))
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return "", true, fmt.Errorf("사전 공유키가 32바이트 base64가 아니다: %s", path)
	}
	// wg에서 전부 0인 키는 키를 쓰지 않는 것과 같다. 그런 파일을 받아들이면
	// psk.mode가 required인데도 실제로는 키 없이 세션이 서고, csa status는
	// 키를 쓴다고 말한다.
	var zero bool = true
	for _, b := range raw {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return "", true, fmt.Errorf("사전 공유키가 전부 0이다. wg에서는 키를 쓰지 않는 것과 같다: %s", path)
	}
	return key, true, nil
}

// LoadPSKs는 모든 상대의 사전 공유키를 읽는다. 없는 상대는 빠진다.
func (c *Config) LoadPSKs() (map[string]string, error) {
	out := map[string]string{}
	for _, peer := range c.Peers {
		key, ok, err := c.LoadPSK(peer.PeerID)
		if err != nil {
			return nil, err
		}
		if ok {
			out[peer.PeerID] = key
		}
	}
	return out, nil
}

// Find는 peer-id로 peer 항목을 찾는다.
func (c *Config) Find(peerID string) *Peer {
	for i := range c.Peers {
		if c.Peers[i].PeerID == peerID {
			return &c.Peers[i]
		}
	}
	return nil
}
