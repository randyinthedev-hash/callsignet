package config

import "testing"

// 같은 설정 둘을 만든다. good은 부를 때마다 다른 임시 디렉터리에 개인키를
// 만들므로, 그대로 견주면 csa.toml이 바뀐 것으로 나온다.
func pair(t *testing.T) (*Config, *Config) {
	t.Helper()
	old, cur := good(t), good(t)
	cur.Self.PrivateKey = old.Self.PrivateKey
	return old, cur
}

// 한 곳만 어긋뜨려 그 차이가 잡히는지 본다. 시험을 쓰는 방식은 설정 검사와 같다.
func TestDiffFindsNothingWhenNothingChanged(t *testing.T) {
	old, cur := pair(t)
	c := Diff(old, cur)
	if c.Any() {
		t.Errorf("바뀐 것이 없어야 하는데 %+v", c)
	}
}

func TestDiffFindsAddedPeer(t *testing.T) {
	old, cur := pair(t)
	cur.Peers = append(cur.Peers, Peer{PeerID: "srv-c", PublicKey: "CCCC", TunnelIP: "10.91.0.3"})
	c := Diff(old, cur)
	if len(c.AddedPeers) != 1 || c.AddedPeers[0] != "srv-c" {
		t.Errorf("더한 상대를 찾아야 하는데 %+v", c)
	}
}

func TestDiffFindsRemovedPeer(t *testing.T) {
	old, cur := pair(t)
	cur.Peers = cur.Peers[:1]
	c := Diff(old, cur)
	if len(c.RemovedPeers) != 1 || c.RemovedPeers[0] != "srv-b" {
		t.Errorf("뺀 상대를 찾아야 하는데 %+v", c)
	}
}

func TestDiffFindsChangedPeer(t *testing.T) {
	cases := map[string]func(p *Peer){
		"공개키":   func(p *Peer) { p.PublicKey = "ZZZZ" },
		"터널 IP": func(p *Peer) { p.TunnelIP = "10.91.0.9" },
		"접속 주소": func(p *Peer) { p.Endpoints = []string{"10.0.5.9:51820"} },
		"서비스":   func(p *Peer) { p.Services = []Service{{App: "report", Port: 9090}} },
		"서비스 개수": func(p *Peer) {
			p.Services = append(p.Services, Service{App: "extra", Port: 9090})
		},
	}
	for what, bend := range cases {
		old, cur := pair(t)
		bend(&cur.Peers[1]) // srv-b
		c := Diff(old, cur)
		if len(c.ChangedPeers) != 1 || c.ChangedPeers[0] != "srv-b" {
			t.Errorf("%s가 바뀐 것을 찾아야 하는데 %+v", what, c)
		}
	}
}

func TestDiffFindsChangedPolicy(t *testing.T) {
	cases := map[string]func(p *Policy){
		"들이는 상대":    func(p *Policy) { p.Inbound[0].Allow = []string{"srv-c"} },
		"들이는 규칙 개수": func(p *Policy) { p.Inbound = append(p.Inbound, Inbound{App: "billing"}) },
		"나가는 곳":     func(p *Policy) { p.Outbound = []string{"srv-b/other"} },
		"IP 대역":     func(p *Policy) { p.Inbound[0].AllowCIDR = []string{"10.0.0.0/8"} },
		"만료 기한":     func(p *Policy) { p.Inbound[0].Expires = "2027-01-01" },
	}
	for what, bend := range cases {
		old, cur := pair(t)
		bend(&cur.Policy)
		if c := Diff(old, cur); !c.PolicyChanged {
			t.Errorf("%s가 바뀐 것을 찾아야 하는데 %+v", what, c)
		}
	}
}

// csa.toml이 바뀐 것은 도는 중에 걸 수 없다. 따로 표시해야 한다.
func TestDiffMarksSelfChange(t *testing.T) {
	old, cur := pair(t)
	cur.Self.Tun.MTU = 1280
	c := Diff(old, cur)
	if !c.SelfChanged {
		t.Errorf("csa.toml이 바뀐 것을 표시해야 하는데 %+v", c)
	}
}

// 이 머신 자신의 공개키와 터널 IP도 도는 중에 걸 수 없다.
func TestDiffMarksSelfPeerChange(t *testing.T) {
	for what, bend := range map[string]func(p *Peer){
		"공개키":   func(p *Peer) { p.PublicKey = "ZZZZ" },
		"터널 IP": func(p *Peer) { p.TunnelIP = "10.91.0.9" },
	} {
		old, cur := pair(t)
		bend(&cur.Peers[0]) // srv-a가 자기 자신이다
		c := Diff(old, cur)
		if !c.SelfPeerChanged {
			t.Errorf("자기 %s가 바뀐 것을 표시해야 하는데 %+v", what, c)
		}
		if len(c.ChangedPeers) != 0 {
			t.Errorf("걸 수 있는 것으로 세면 안 된다: %+v", c)
		}
	}
}

// 자기 서비스 목록이 바뀐 것은 걸 수 있다. 인터페이스를 다시 만들 일이 없다.
func TestDiffAllowsSelfServiceChange(t *testing.T) {
	old, cur := pair(t)
	cur.Peers[0].Services = []Service{{App: "billing", Port: 9090}}
	c := Diff(old, cur)
	if c.SelfPeerChanged || c.SelfChanged {
		t.Errorf("걸 수 있는 것이어야 하는데 %+v", c)
	}
	if len(c.ChangedPeers) != 1 || c.ChangedPeers[0] != "srv-a" {
		t.Errorf("고친 상대로 세야 하는데 %+v", c)
	}
}
