// Package policy는 csa가 연결을 허용할지 판단하는 규칙을 다룬다.
package policy

import (
	"fmt"
	"net/netip"

	"github.com/randyinthedev-hash/callsignet/internal/config"
)

// Decision은 판단 결과다.
type Decision struct {
	Allow  bool
	Reason string
}

// Rules는 설정에서 뽑아낸 허용 목록이다.
type Rules struct {
	// selfIP는 이 머신의 터널 IP다.
	selfIP netip.Addr
	// peerByIP는 터널 IP로 상대의 peer-id를 찾는다. wg가 출발지를 검사한 뒤이므로
	// 이 대응은 위조할 수 없다.
	peerByIP map[netip.Addr]string
	// inbound는 이 머신의 포트에 붙어도 되는 상대다. 포트 → peer-id 집합.
	inbound map[uint16]map[string]bool
	// appByPort는 이 머신의 포트가 어느 앱인지 알려 준다. 기록에 쓴다.
	appByPort map[uint16]string
	// outbound는 이 머신이 붙어도 되는 상대다. 터널 IP와 포트의 쌍.
	outbound map[target]bool
	// inboundPeers와 outboundPeers는 그 상대와 통신할 권한이 하나라도 있는지
	// 알려 준다. 포트가 없는 ICMP를 판단할 때 쓴다.
	inboundPeers  map[string]bool
	outboundPeers map[netip.Addr]bool
}

type target struct {
	ip   netip.Addr
	port uint16
}

// New는 설정에서 허용 목록을 만든다.
func New(c *config.Config) (*Rules, error) {
	self := c.Find(c.Self.PeerID)
	if self == nil {
		return nil, fmt.Errorf("csa.toml의 peer-id가 peers.toml에 없다: %s", c.Self.PeerID)
	}
	selfIP, err := netip.ParseAddr(self.TunnelIP)
	if err != nil {
		return nil, fmt.Errorf("이 머신의 터널 IP를 읽을 수 없다: %s", self.TunnelIP)
	}

	r := &Rules{
		selfIP:    selfIP,
		peerByIP:  map[netip.Addr]string{},
		inbound:   map[uint16]map[string]bool{},
		appByPort: map[uint16]string{},
		outbound:  map[target]bool{},

		inboundPeers:  map[string]bool{},
		outboundPeers: map[netip.Addr]bool{},
	}
	portOf := map[string]map[string]uint16{} // peer-id → app → 포트
	for _, peer := range c.Peers {
		ip, err := netip.ParseAddr(peer.TunnelIP)
		if err != nil {
			return nil, fmt.Errorf("터널 IP를 읽을 수 없다: %s의 %s", peer.PeerID, peer.TunnelIP)
		}
		r.peerByIP[ip] = peer.PeerID
		portOf[peer.PeerID] = map[string]uint16{}
		for _, svc := range peer.Services {
			portOf[peer.PeerID][svc.App] = uint16(svc.Port)
		}
	}
	for app, port := range portOf[c.Self.PeerID] {
		r.appByPort[port] = app
	}

	for _, in := range c.Policy.Inbound {
		port, ok := portOf[c.Self.PeerID][in.App]
		if !ok {
			return nil, fmt.Errorf("inbound가 가리키는 app이 이 머신의 서비스에 없다: %s", in.App)
		}
		if r.inbound[port] == nil {
			r.inbound[port] = map[string]bool{}
		}
		for _, id := range in.Allow {
			r.inbound[port][id] = true
			r.inboundPeers[id] = true
		}
	}

	for _, t := range c.Policy.Outbound {
		id, app, ok := cut(t)
		if !ok {
			return nil, fmt.Errorf("outbound는 peer-id/app 형태여야 한다: %s", t)
		}
		port, ok := portOf[id][app]
		if !ok {
			return nil, fmt.Errorf("outbound가 가리키는 서비스가 없다: %s", t)
		}
		peer := c.Find(id)
		ip, _ := netip.ParseAddr(peer.TunnelIP)
		r.outbound[target{ip, port}] = true
		r.outboundPeers[ip] = true
	}
	return r, nil
}

// Inbound는 들어온 패킷을 앱에게 넘길지 판단한다. src는 복호화한 패킷의
// 출발지 터널 IP이고, wg가 이미 그 값이 그 상대의 것임을 검사했다.
func (r *Rules) Inbound(src netip.Addr, dstPort uint16) Decision {
	id, ok := r.peerByIP[src]
	if !ok {
		return Decision{false, "보낸 쪽의 peer-id를 확정하지 못했다"}
	}
	allowed, ok := r.inbound[dstPort]
	if !ok {
		return Decision{false, fmt.Sprintf("%s에게 열어 둔 포트가 아니다: %d", id, dstPort)}
	}
	if !allowed[id] {
		return Decision{false, fmt.Sprintf("정책에 없다: %s에서 %s", id, r.appName(dstPort))}
	}
	return Decision{true, ""}
}

// Outbound는 나가는 패킷을 암호화할지 판단한다. 여러 겹 방어 가운데 한 겹이며
// 최종 판단이 아니다. 최종 판단은 받는 쪽 csa가 한다.
func (r *Rules) Outbound(dst netip.Addr, dstPort uint16) Decision {
	if r.outbound[target{dst, dstPort}] {
		return Decision{true, ""}
	}
	if id, ok := r.peerByIP[dst]; ok {
		return Decision{false, fmt.Sprintf("정책에 없다: %s의 %d 포트", id, dstPort)}
	}
	return Decision{false, fmt.Sprintf("모르는 상대다: %s", dst)}
}

// InboundICMP는 들어온 ICMP를 앱에게 넘길지 판단한다. ICMP에는 포트가 없어
// 어느 앱으로 가는지 가릴 수 없다. 그래서 그 상대에게 열어 둔 서비스가 하나라도
// 있으면 허용한다. 통신할 권한이 있는 상대끼리 진단할 수 있어야 하기 때문이다.
func (r *Rules) InboundICMP(src netip.Addr) Decision {
	id, ok := r.peerByIP[src]
	if !ok {
		return Decision{false, "보낸 쪽의 peer-id를 확정하지 못했다"}
	}
	if !r.inboundPeers[id] {
		return Decision{false, fmt.Sprintf("열어 둔 서비스가 없는 상대다: %s", id)}
	}
	return Decision{true, ""}
}

// OutboundICMP는 나가는 ICMP를 암호화할지 판단한다. 판단 기준은 InboundICMP와 같다.
func (r *Rules) OutboundICMP(dst netip.Addr) Decision {
	if r.outboundPeers[dst] {
		return Decision{true, ""}
	}
	if id, ok := r.peerByIP[dst]; ok {
		return Decision{false, fmt.Sprintf("붙어도 되는 서비스가 없는 상대다: %s", id)}
	}
	return Decision{false, fmt.Sprintf("모르는 상대다: %s", dst)}
}

// PeerOf는 터널 IP로 peer-id를 찾는다. 기록에 쓴다.
func (r *Rules) PeerOf(ip netip.Addr) (string, bool) {
	id, ok := r.peerByIP[ip]
	return id, ok
}

// SelfIP는 이 머신의 터널 IP다.
func (r *Rules) SelfIP() netip.Addr { return r.selfIP }

func (r *Rules) appName(port uint16) string {
	if app, ok := r.appByPort[port]; ok {
		return app
	}
	return fmt.Sprintf("포트 %d", port)
}

func cut(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
