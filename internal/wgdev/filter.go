//go:build linux

package wgdev

import (
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/randyinthedev-hash/callsignet/internal/policy"
	"golang.zx2c4.com/wireguard/tun"
)

// filter는 TUN 인터페이스를 감싸 정책을 집행한다.
//
// wg는 이 인터페이스에서 읽은 패킷을 암호화해 내보내고, 복호화한 패킷을 이
// 인터페이스에 쓴다. 그래서 읽는 자리가 나가는 쪽 걸러내기이고, 쓰는 자리가
// 받는 쪽 집행이다.
type filter struct {
	tun.Device
	// rules는 csa reload가 통째로 갈아 끼운다. 패킷을 보는 쪽은 포인터 하나를
	// 읽으므로 반쯤 바뀐 규칙을 보지 않는다.
	rules atomic.Pointer[policy.Rules]
	logf  func(string, ...any)
	// flows는 연결마다 한 번만 적으려고 둔다. conns는 csa가 들인 연결을 기억해
	// 되돌아오는 패킷을 들이려고 둔다. 기억하는 시간이 달라 따로 둔다.
	flows *flows
	conns *flows
	// maxMSS는 이 터널이 나를 수 있는 TCP 세그먼트 크기다. MTU에서 IP 헤더와
	// TCP 헤더 각각 20바이트를 뺀 값이다.
	maxMSS uint16
	// clamped는 지금까지 깎은 횟수다. told는 처음 깎았을 때 한 번만 적으려고 둔다.
	clamped atomic.Uint64
	told    atomic.Bool
	// observe는 그 상대의 지금 접속 주소를 돌려준다. wg가 복호화하면서 짝을
	// 맞춰 둔 값이며, 연결이 열리는 그 순간에 읽어 기록에 붙인다.
	observe func(peerID string) string
}

// Read는 앱이 보낸 패킷을 읽어 정책에 없는 것을 버린다. 버릴 때는 앱에게
// 거절을 알린다.
func (f *filter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := f.Device.Read(bufs, sizes, offset)
	if err != nil || n == 0 {
		return n, err
	}
	kept := 0
	for i := 0; i < n; i++ {
		pkt := bufs[i][offset : offset+sizes[i]]
		if d, ok := f.allowOut(pkt); !ok {
			f.reject(pkt, d)
			continue
		}
		f.clamp(pkt)
		if kept != i {
			copy(bufs[kept][offset:], pkt)
			sizes[kept] = sizes[i]
		}
		kept++
	}
	return kept, nil
}

// Write는 복호화한 패킷을 앱에게 넘기기 전에 정책을 본다. 통과한 것만 쓴다.
func (f *filter) Write(bufs [][]byte, offset int) (int, error) {
	keep := make([][]byte, 0, len(bufs))
	for _, b := range bufs {
		if len(b) <= offset {
			continue
		}
		if f.allowIn(b[offset:]) {
			f.clamp(b[offset:])
			keep = append(keep, b)
		}
	}
	if len(keep) == 0 {
		return 0, nil
	}
	return f.Device.Write(keep, offset)
}

// clamp는 TCP SYN에 실린 최대 세그먼트 크기를 이 터널이 나를 수 있는 크기로
// 깎는다. 나가는 쪽과 받는 쪽 양쪽에서 한다. 상대가 깎지 않고 보내는 경우가
// 있기 때문이다.
//
// 처음 깎았을 때 한 번만 적는다. 연결마다 적으면 기록이 두 배가 된다. 몇 번
// 깎았는지는 csa status가 보여 준다.
func (f *filter) clamp(pkt []byte) {
	if !policy.ClampMSS(pkt, f.maxMSS) {
		return
	}
	f.clamped.Add(1)
	if f.told.CompareAndSwap(false, true) {
		f.logf("TCP 최대 세그먼트 크기를 깎았습니다. 이 터널이 나를 수 있는 크기는 %d바이트입니다."+
			" 앞으로는 적지 않고 csa status에 셉니다.", f.maxMSS)
	}
}

func (f *filter) allowOut(pkt []byte) (policy.Decision, bool) {
	p, ok := policy.Parse(pkt)
	if !ok {
		// IPv4가 아닌 것은 이 터널로 나르지 않는다. 커널이 만든 IPv6 이웃 탐색
		// 같은 것이 여기 걸리므로 기록하지 않는다.
		return policy.Decision{}, false
	}
	r := f.rules.Load()
	var d policy.Decision
	if p.HasPorts() {
		d = r.Outbound(p.Dst, p.DstPort)
	} else {
		d = r.OutboundICMP(p.Dst)
	}
	k := keyOf(p)
	// 정책에 없어도 csa가 앞서 들인 연결의 답이면 내보낸다. 정책은 연결을 여는
	// 쪽만 본다. 답의 목적지는 상대 앱의 임시 포트라 어느 서비스에도 적혀 있지
	// 않다. 이것을 막으면 TCP가 서지 않는다.
	if !d.Allow && f.conns.IsReply(k) {
		return policy.Decision{Allow: true}, true
	}
	if !f.flows.First(k) {
		return d, d.Allow
	}
	if d.Allow {
		f.conns.Allow(k)
		f.logf("나가는 연결을 엽니다. 상대 %s, 목적지 %s", f.peerName(r, p.Dst), portName(p))
	} else {
		f.logf("나가는 연결을 막았습니다. 목적지 %s, 까닭 %s", p.Dst, d.Reason)
	}
	return d, d.Allow
}

func (f *filter) allowIn(pkt []byte) bool {
	p, ok := policy.Parse(pkt)
	if !ok {
		return false
	}
	r := f.rules.Load()
	var d policy.Decision
	if p.HasPorts() {
		var from netip.Addr
		if r.NeedsSource(p.DstPort) {
			from = f.observedAddr(r, p.Src)
		}
		d = r.Inbound(p.Src, p.DstPort, from)
	} else {
		var from netip.Addr
		if r.NeedsSourceICMP() {
			from = f.observedAddr(r, p.Src)
		}
		d = r.InboundICMP(p.Src, from)
	}
	k := keyOf(p)
	// 나가는 쪽과 같은 까닭이다. csa가 앞서 내보낸 연결의 답은 정책에 없어도 들인다.
	if !d.Allow && f.conns.IsReply(k) {
		return true
	}
	if !f.flows.First(k) {
		return d.Allow
	}
	id := f.peerName(r, p.Src)
	if !d.Allow {
		f.logf("들어온 연결을 막았습니다. 상대 %s, 출발지 %s, 까닭 %s", id, p.Src, d.Reason)
		return false
	}
	f.conns.Allow(k)
	f.logf("들어온 연결을 받았습니다. 상대 %s, 관측한 출발지 %s, 목적지 %s",
		id, f.observed(r, p.Src), portName(p))
	return true
}

// peerName은 터널 IP에 이름을 붙인다. 모르는 주소면 주소를 그대로 쓴다.
func (f *filter) peerName(r *policy.Rules, ip netip.Addr) string {
	if id, ok := r.PeerOf(ip); ok {
		return id
	}
	return ip.String()
}

// observedAddr는 그 상대에게서 패킷이 실제로 온 주소를 돌려준다. 포트는 뗀다.
// IP 대역 규칙이 재는 값이 이것이다. 대역을 보는 규칙이 있는 포트일 때만 부른다.
func (f *filter) observedAddr(r *policy.Rules, ip netip.Addr) netip.Addr {
	id, ok := r.PeerOf(ip)
	if !ok || f.observe == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(f.observe(id))
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// observed는 그 상대에게서 패킷이 실제로 온 주소를 기록에 적을 모습으로
// 돌려준다. 포트를 붙인 채로 적는다.
func (f *filter) observed(r *policy.Rules, ip netip.Addr) string {
	id, ok := r.PeerOf(ip)
	if !ok || f.observe == nil {
		return "알 수 없음"
	}
	if ep := f.observe(id); ep != "" {
		return ep
	}
	return "알 수 없음"
}

func portName(p policy.Packet) string {
	if p.HasPorts() {
		return fmt.Sprintf("%s:%d", p.Dst, p.DstPort)
	}
	return fmt.Sprintf("%s(포트 없음)", p.Dst)
}

// reject는 앱에게 거절을 알린다. 감싼 인터페이스에 바로 쓰므로 다시 걸러지지
// 않는다.
func (f *filter) reject(pkt []byte, d policy.Decision) {
	icmp := policy.RejectICMP(pkt)
	if icmp == nil {
		return
	}
	buf := make([]byte, 16+len(icmp))
	copy(buf[16:], icmp)
	f.Device.Write([][]byte{buf}, 16)
}
