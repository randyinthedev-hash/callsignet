//go:build linux

package wgdev

import (
	"net/netip"
	"sync"
	"time"

	"github.com/randyinthedev-hash/callsignet/internal/policy"
)

// flowKey는 연결 하나를 가리킨다. 설계에서 말하는 flow가 이것이다.
type flowKey struct {
	src, dst     netip.Addr
	sport, dport uint16
	proto        uint8
}

func keyOf(p policy.Packet) flowKey {
	return flowKey{p.Src, p.Dst, p.SrcPort, p.DstPort, p.Proto}
}

// flows는 지금 오가는 연결을 기억한다. 연결마다 한 번만 적으려는 것이다.
// 패킷마다 적으면 로그가 쓸모없어진다.
type flows struct {
	mu   sync.Mutex
	seen map[flowKey]time.Time
	ttl  time.Duration
	max  int
}

func newFlows() *flows {
	return &flows{seen: map[flowKey]time.Time{}, ttl: 2 * time.Minute, max: 4096}
}

// First는 이 연결을 처음 보았는지 알려 준다. 처음이면 true를 돌려주고 기억한다.
func (f *flows) First(k flowKey) bool {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if last, ok := f.seen[k]; ok && now.Sub(last) < f.ttl {
		f.seen[k] = now
		return false
	}
	if len(f.seen) >= f.max {
		f.sweep(now)
	}
	f.seen[k] = now
	return true
}

// sweep은 오래된 것을 버린다. 자물쇠를 쥔 채로 부른다.
func (f *flows) sweep(now time.Time) {
	for k, t := range f.seen {
		if now.Sub(t) >= f.ttl {
			delete(f.seen, k)
		}
	}
	// 그래도 가득하면 절반을 버린다. 기억이 무한히 늘지 않게 하려는 것이다.
	if len(f.seen) >= f.max {
		n := len(f.seen) / 2
		for k := range f.seen {
			delete(f.seen, k)
			if n--; n <= 0 {
				break
			}
		}
	}
}
