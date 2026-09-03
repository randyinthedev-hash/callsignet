// Package policy는 csa가 연결을 허용할지 판단하는 규칙을 다룬다.
package policy

import (
	"fmt"
	"net/netip"
	"time"

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
	// inbound는 이 머신의 포트마다 걸린 규칙이다. policy.toml의 [[inbound]]
	// 하나가 규칙 하나다. 한 포트에 규칙이 여럿이면 하나만 만족해도 들인다.
	inbound map[uint16][]*rule
	// allInbound는 포트를 가리지 않은 규칙 전부다. 포트가 없는 ICMP에 쓴다.
	allInbound []*rule
	// needSource는 그 포트의 규칙이 관측한 출발지를 보는지 알려 준다. 보지
	// 않아도 되면 wg에게 묻지 않는다.
	needSource     map[uint16]bool
	needSourceICMP bool
	// appByPort는 이 머신의 포트가 어느 앱인지 알려 준다. 기록에 쓴다.
	appByPort map[uint16]string
	// outbound는 이 머신이 붙어도 되는 상대다. 터널 IP와 포트의 쌍.
	outbound map[target]bool
	// outboundPeers는 그 상대에게 붙을 권한이 하나라도 있는지 알려 준다.
	// 포트가 없는 ICMP를 판단할 때 쓴다.
	outboundPeers map[netip.Addr]bool
}

// dateLayout은 expires에 적는 날짜의 모양이다.
const dateLayout = "2006-01-02"

// rule은 들이는 규칙 하나다. policy.toml의 [[inbound]] 하나에서 온다.
type rule struct {
	// app은 이 규칙이 지키는 앱이다. 기록에 쓴다.
	app string
	// peers는 들일 상대다. 비어 있으면 상대를 가리지 않는다.
	peers map[string]bool
	// cidrs는 들일 출발지 대역이다. 비어 있으면 대역을 가리지 않는다. 여기서
	// 재는 것은 터널 IP가 아니라 csa가 wg에게 물어 얻은 바깥 출발지다.
	cidrs []netip.Prefix
	// expires는 이 규칙이 죽는 날이다. 그날 0시에 죽는다. 비어 있으면 죽지 않는다.
	expires time.Time
}

// allows는 그 상대가 그 출발지에서 이 규칙을 만족하는지 본다.
//
// 조건을 하나도 적지 않은 규칙은 아무도 들이지 않는다. 앱 이름만 적어 둔 것을
// 열어 두려는 뜻으로 읽지 않는다.
func (u *rule) allows(id string, from netip.Addr) bool {
	if len(u.peers) == 0 && len(u.cidrs) == 0 {
		return false
	}
	if u.dead() {
		return false
	}
	if len(u.peers) > 0 && !u.peers[id] {
		return false
	}
	if len(u.cidrs) > 0 && !inAny(u.cidrs, from) {
		return false
	}
	return true
}

// dead는 기한이 지났는지 본다. csa가 오래 도는 동안 기한이 지나갈 수 있으므로
// 설정을 읽을 때만 보지 않고 판단할 때마다 본다.
func (u *rule) dead() bool {
	return !u.expires.IsZero() && time.Now().After(u.expires)
}

func inAny(cidrs []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
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
		selfIP:     selfIP,
		peerByIP:   map[netip.Addr]string{},
		inbound:    map[uint16][]*rule{},
		appByPort:  map[uint16]string{},
		outbound:   map[target]bool{},
		needSource: map[uint16]bool{},

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
		u := &rule{app: in.App, peers: map[string]bool{}}
		for _, id := range in.Allow {
			u.peers[id] = true
		}
		for _, s := range in.AllowCIDR {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("inbound의 allow-cidr를 읽을 수 없다: app %s의 %s", in.App, s)
			}
			u.cidrs = append(u.cidrs, pfx.Masked())
		}
		if in.Expires != "" {
			t, err := time.ParseInLocation(dateLayout, in.Expires, time.Local)
			if err != nil {
				return nil, fmt.Errorf("expires를 읽을 수 없다: app %s의 %s", in.App, in.Expires)
			}
			u.expires = t
		}
		r.inbound[port] = append(r.inbound[port], u)
		r.allInbound = append(r.allInbound, u)
		if len(u.cidrs) > 0 {
			r.needSource[port] = true
			r.needSourceICMP = true
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

// NeedsSource는 그 포트의 규칙이 관측한 출발지를 보는지 알려 준다. csa는 참일
// 때만 wg에게 출발지를 묻는다. 묻는 것이 값싸지 않기 때문이다.
func (r *Rules) NeedsSource(dstPort uint16) bool { return r.needSource[dstPort] }

// NeedsSourceICMP는 ICMP를 판단할 때 관측한 출발지가 필요한지 알려 준다.
func (r *Rules) NeedsSourceICMP() bool { return r.needSourceICMP }

// Inbound는 들어온 패킷을 앱에게 넘길지 판단한다.
//
// src는 복호화한 패킷의 출발지 터널 IP이고, wg가 이미 그 값이 그 상대의 것임을
// 검사했다. from은 csa가 관측한 바깥 출발지다. NeedsSource가 거짓이면 비어 있어도
// 되고, 그때는 아무 규칙도 그 값을 보지 않는다.
func (r *Rules) Inbound(src netip.Addr, dstPort uint16, from netip.Addr) Decision {
	id, ok := r.peerByIP[src]
	if !ok {
		return Decision{false, "보낸 쪽의 peer-id를 확정하지 못했다"}
	}
	rules, ok := r.inbound[dstPort]
	if !ok {
		return Decision{false, fmt.Sprintf("%s에게 열어 둔 포트가 아니다: %d", id, dstPort)}
	}
	for _, u := range rules {
		if u.allows(id, from) {
			return Decision{true, ""}
		}
	}
	if why, ok := banReason(rules, id, from); ok {
		return Decision{false, why}
	}
	return Decision{false, fmt.Sprintf("정책에 없다: %s에서 %s", id, r.appName(dstPort))}
}

// banReason은 상대는 맞는데 대역이나 기한 때문에 막힌 것인지 갈라 준다. 무엇을
// 고쳐야 하는지 운영자가 알 수 있게 하려는 것이다.
func banReason(rules []*rule, id string, from netip.Addr) (string, bool) {
	for _, u := range rules {
		if len(u.peers) > 0 && !u.peers[id] {
			continue
		}
		if u.dead() {
			return fmt.Sprintf("규칙의 기한이 지났다: app %s, 기한 %s",
				u.app, u.expires.Format(dateLayout)), true
		}
		if len(u.cidrs) > 0 {
			return fmt.Sprintf("허용 대역 밖에서 왔다: 상대 %s, app %s, 관측한 출발지 %s",
				id, u.app, source(from)), true
		}
	}
	return "", false
}

func source(ip netip.Addr) string {
	if !ip.IsValid() {
		return "알 수 없음"
	}
	return ip.String()
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

// InboundICMP는 들어온 ICMP를 앱에게 넘길지 판단한다.
//
// ICMP에는 포트가 없어 어느 앱으로 가는지 가릴 수 없다. 그래서 그 상대를 들이는
// 규칙이 하나라도 있으면 허용한다. 통신할 권한이 있는 상대끼리 진단할 수 있어야
// 하기 때문이다. 그 규칙에 대역이 걸려 있으면 대역도 함께 본다.
func (r *Rules) InboundICMP(src, from netip.Addr) Decision {
	id, ok := r.peerByIP[src]
	if !ok {
		return Decision{false, "보낸 쪽의 peer-id를 확정하지 못했다"}
	}
	for _, u := range r.allInbound {
		if u.allows(id, from) {
			return Decision{true, ""}
		}
	}
	if why, ok := banReason(r.allInbound, id, from); ok {
		return Decision{false, why}
	}
	return Decision{false, fmt.Sprintf("열어 둔 서비스가 없는 상대다: %s", id)}
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
