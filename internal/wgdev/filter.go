//go:build linux

package wgdev

import (
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
	if !d.Allow {
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
	if !d.Allow {
		f.logf("들어온 연결을 막았습니다. 출발지 %s, 까닭 %s", p.Src, d.Reason)
		return false
	}
	return true
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
