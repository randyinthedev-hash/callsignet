//go:build linux

package wgdev

import (
	"fmt"
	"net/netip"

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
	rules *policy.Rules
	logf  func(string, ...any)
	flows *flows
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
			keep = append(keep, b)
		}
	}
	if len(keep) == 0 {
		return 0, nil
	}
	return f.Device.Write(keep, offset)
}

func (f *filter) allowOut(pkt []byte) (policy.Decision, bool) {
	p, ok := policy.Parse(pkt)
	if !ok {
		// IPv4가 아닌 것은 이 터널로 나르지 않는다. 커널이 만든 IPv6 이웃 탐색
		// 같은 것이 여기 걸리므로 기록하지 않는다.
		return policy.Decision{}, false
	}
	var d policy.Decision
	if p.HasPorts() {
		d = f.rules.Outbound(p.Dst, p.DstPort)
	} else {
		d = f.rules.OutboundICMP(p.Dst)
	}
	if !f.flows.First(keyOf(p)) {
		return d, d.Allow
	}
	if d.Allow {
		f.logf("나가는 연결을 엽니다. 상대 %s, 목적지 %s", f.peerName(p.Dst), portName(p))
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
	var d policy.Decision
	if p.HasPorts() {
		d = f.rules.Inbound(p.Src, p.DstPort)
	} else {
		d = f.rules.InboundICMP(p.Src)
	}
	if !f.flows.First(keyOf(p)) {
		return d.Allow
	}
	id := f.peerName(p.Src)
	if !d.Allow {
		f.logf("들어온 연결을 막았습니다. 상대 %s, 출발지 %s, 까닭 %s", id, p.Src, d.Reason)
		return false
	}
	f.logf("들어온 연결을 받았습니다. 상대 %s, 관측한 출발지 %s, 목적지 %s",
		id, f.observed(p.Src), portName(p))
	return true
}

// peerName은 터널 IP에 이름을 붙인다. 모르는 주소면 주소를 그대로 쓴다.
func (f *filter) peerName(ip netip.Addr) string {
	if id, ok := f.rules.PeerOf(ip); ok {
		return id
	}
	return ip.String()
}

// observed는 그 상대에게서 패킷이 실제로 온 주소를 돌려준다.
func (f *filter) observed(ip netip.Addr) string {
	id, ok := f.rules.PeerOf(ip)
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
	icmp := policy.RejectICMP(pkt, f.rules.SelfIP())
	if icmp == nil {
		return
	}
	buf := make([]byte, 16+len(icmp))
	copy(buf[16:], icmp)
	f.Device.Write([][]byte{buf}, 16)
}
