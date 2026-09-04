// Package config는 csa가 읽는 설정 파일을 다룬다.
//
// 설정은 /etc/callsignet/ 아래에 셋으로 나뉜다. csa.toml은 이 머신 자신에 대한
// 값이고, peers.toml은 모든 peer의 이름과 키와 주소와 서비스이며, policy.toml은
// 이 머신의 정책이다.
package config

import (
	"fmt"
	"path/filepath"

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
	if _, err := toml.DecodeFile(filepath.Join(dir, "csa.toml"), &c.Self); err != nil {
		return nil, fmt.Errorf("csa.toml을 읽지 못했다: %w", err)
	}
	var pf peersFile
	if _, err := toml.DecodeFile(filepath.Join(dir, "peers.toml"), &pf); err != nil {
		return nil, fmt.Errorf("peers.toml을 읽지 못했다: %w", err)
	}
	c.Peers = pf.Peer
	if _, err := toml.DecodeFile(filepath.Join(dir, "policy.toml"), &c.Policy); err != nil {
		return nil, fmt.Errorf("policy.toml을 읽지 못했다: %w", err)
	}
	return &c, nil
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
