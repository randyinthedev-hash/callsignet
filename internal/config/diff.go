package config

import "sort"

// Changes는 도는 csa가 읽고 있던 설정과 새로 읽은 설정의 차이다. csa reload가
// 무엇을 걸 수 있고 무엇을 걸 수 없는지 여기서 갈린다.
type Changes struct {
	AddedPeers   []string
	RemovedPeers []string
	ChangedPeers []string

	PolicyChanged bool

	// SelfChanged는 csa.toml이 바뀐 것이다. 거기 적힌 값은 TUN 인터페이스와
	// 개인키와 리슨 주소를 정하므로 도는 중에 바꿀 수 없다.
	SelfChanged bool
	// SelfPeerChanged는 peers.toml에서 이 머신 자신의 공개키나 터널 IP가 바뀐
	// 것이다. 이것도 도는 중에 바꿀 수 없다. 자기 서비스 목록이 바뀐 것은
	// 여기에 들지 않는다. 그것은 걸 수 있다.
	SelfPeerChanged bool
}

// Any는 바뀐 것이 하나라도 있는지 알려준다.
func (c Changes) Any() bool {
	return len(c.AddedPeers) > 0 || len(c.RemovedPeers) > 0 || len(c.ChangedPeers) > 0 ||
		c.PolicyChanged || c.SelfChanged || c.SelfPeerChanged
}

// Diff는 두 설정을 견준다. peer는 peer-id로 짝을 맞춘다.
func Diff(old, cur *Config) Changes {
	var c Changes
	c.SelfChanged = !sameSelf(old.Self, cur.Self)
	c.PolicyChanged = !samePolicy(old.Policy, cur.Policy)

	oldByID := byID(old.Peers)
	curByID := byID(cur.Peers)

	for id := range oldByID {
		if _, ok := curByID[id]; !ok {
			c.RemovedPeers = append(c.RemovedPeers, id)
		}
	}
	for id, p := range curByID {
		o, had := oldByID[id]
		if !had {
			c.AddedPeers = append(c.AddedPeers, id)
			continue
		}
		if samePeer(o, p) {
			continue
		}
		// 이 머신 자신의 공개키와 터널 IP는 인터페이스를 다시 만들어야 바뀐다.
		if id == cur.Self.PeerID && (o.PublicKey != p.PublicKey || o.TunnelIP != p.TunnelIP) {
			c.SelfPeerChanged = true
			continue
		}
		c.ChangedPeers = append(c.ChangedPeers, id)
	}
	sort.Strings(c.AddedPeers)
	sort.Strings(c.RemovedPeers)
	sort.Strings(c.ChangedPeers)
	return c
}

// sameSelf는 csa.toml에서 온 값이 같은지 본다. Guard가 슬라이스를 담고 있어
// 구조체끼리 그냥 견줄 수 없다.
func sameSelf(a, b Self) bool {
	if a.PeerID != b.PeerID || a.PrivateKey != b.PrivateKey || a.Domain != b.Domain ||
		a.TunnelCIDR != b.TunnelCIDR || a.ListenPort != b.ListenPort ||
		a.Tun != b.Tun || a.DNS != b.DNS || a.Guard.Mode != b.Guard.Mode {
		return false
	}
	return sameInts(a.Guard.KeepTCP, b.Guard.KeepTCP) && sameInts(a.Guard.KeepUDP, b.Guard.KeepUDP)
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func byID(peers []Peer) map[string]Peer {
	m := make(map[string]Peer, len(peers))
	for _, p := range peers {
		m[p.PeerID] = p
	}
	return m
}

func samePeer(a, b Peer) bool {
	if a.PublicKey != b.PublicKey || a.TunnelIP != b.TunnelIP {
		return false
	}
	if !sameStrings(a.Endpoints, b.Endpoints) {
		return false
	}
	if len(a.Services) != len(b.Services) {
		return false
	}
	for i := range a.Services {
		if a.Services[i] != b.Services[i] {
			return false
		}
	}
	return true
}

func samePolicy(a, b Policy) bool {
	if !sameStrings(a.Outbound, b.Outbound) {
		return false
	}
	if len(a.Inbound) != len(b.Inbound) {
		return false
	}
	for i := range a.Inbound {
		x, y := a.Inbound[i], b.Inbound[i]
		if x.App != y.App || x.Expires != y.Expires {
			return false
		}
		if !sameStrings(x.Allow, y.Allow) || !sameStrings(x.AllowCIDR, y.AllowCIDR) {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
