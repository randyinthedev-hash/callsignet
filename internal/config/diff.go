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

	// PSKPeers는 사전 공유키가 바뀐 상대다. 이 값은 TOML이 아니라 파일에 있다.
	// csa.toml과 peers.toml과 policy.toml만 견주면 키를 갈아 끼운 것이 드러나지
	// 않는다. 그러면 csa는 「바뀐 것이 없습니다」라고 답하고 옛 키로 계속 돈다.
	//
	// 상대의 이름만 담는다. 키 자체를 담으면 보고와 로그로 새어 나간다.
	PSKPeers []string
}

// Any는 바뀐 것이 하나라도 있는지 알려준다.
func (c Changes) Any() bool {
	return len(c.AddedPeers) > 0 || len(c.RemovedPeers) > 0 || len(c.ChangedPeers) > 0 ||
		len(c.PSKPeers) > 0 || c.PolicyChanged || c.SelfChanged || c.SelfPeerChanged
}

// Diff는 두 설정을 견준다. peer는 peer-id로 짝을 맞춘다.
func Diff(old, cur *Config) Changes {
	var c Changes
	c.SelfChanged = !sameSelf(old.Self, cur.Self)
	c.PolicyChanged = !samePolicy(old.Policy, cur.Policy)
	c.PSKPeers = changedPSK(old, cur)

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

// changedPSK는 사전 공유키가 바뀐 상대를 찾는다.
//
// 두 설정이 이미 읽어 둔 값을 견준다. 여기서 파일을 새로 읽지 않는다. 도는 csa가
// 쓰고 있는 키와 새로 읽은 키를 견주어야 하는데, 도는 csa가 쓰는 것은 그 설정이
// 읽어 둔 값이기 때문이다.
func changedPSK(old, cur *Config) []string {
	a, b := old.Secrets().PSK, cur.Secrets().PSK
	var out []string
	seen := map[string]bool{}
	for _, m := range []map[string]string{a, b} {
		for id := range m {
			if seen[id] {
				continue
			}
			seen[id] = true
			if a[id] != b[id] {
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

// sameSelf는 csa.toml에서 온 값이 같은지 본다. Guard가 슬라이스를 담고 있어
// 구조체끼리 그냥 견줄 수 없다.
func sameSelf(a, b Self) bool {
	if a.PeerID != b.PeerID || a.PrivateKey != b.PrivateKey || a.Domain != b.Domain ||
		a.TunnelCIDR != b.TunnelCIDR || a.ListenPort != b.ListenPort ||
		a.Tun != b.Tun || a.DNS != b.DNS || a.Guard.Mode != b.Guard.Mode ||
		a.PSK != b.PSK {
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
