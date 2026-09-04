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

// reverse는 되돌아오는 방향의 열쇠다.
func (k flowKey) reverse() flowKey {
	return flowKey{k.dst, k.src, k.dport, k.sport, k.proto}
}

// 기억하는 시간과 개수. csa는 두 벌을 따로 둔다.
//
// 적기용은 짧게 둔다. 연결마다 한 번만 적으려는 것이므로 오래 들고 있을 까닭이
// 없다. 들인 연결용은 길게 둔다. 오래 쉬다가 다시 말을 거는 연결이 있기
// 때문이다. 오가는 동안에는 볼 때마다 시각을 새로 적으므로 살아 있는 연결은
// 이 시간과 상관없이 남는다.
const (
	logTTL  = 2 * time.Minute
	logMax  = 4096
	connTTL = time.Hour
	connMax = 16384
)

// flowState는 연결 하나에 대해 기억하는 것이다.
type flowState struct {
	at time.Time
	// allowed는 csa가 이 연결을 들였다는 뜻이다. 되돌아오는 패킷을 들일지
	// 정할 때 본다.
	allowed bool
}

// flows는 지금 오가는 연결을 기억한다. 두 가지에 쓴다. 연결마다 한 번만 적는
// 것과, 들인 연결의 되돌아오는 패킷을 들이는 것이다. 패킷마다 적으면 로그가
// 쓸모없어지고, 되돌아오는 패킷을 기억하지 않으면 TCP가 서지 않는다.
type flows struct {
	mu   sync.Mutex
	seen map[flowKey]flowState
	ttl  time.Duration
	max  int
}

func newFlows(ttl time.Duration, max int) *flows {
	return &flows{seen: map[flowKey]flowState{}, ttl: ttl, max: max}
}

// First는 이 연결을 처음 보았는지 알려 준다. 처음이면 true를 돌려주고 기억한다.
func (f *flows) First(k flowKey) bool {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.seen[k]; ok && now.Sub(e.at) < f.ttl {
		e.at = now
		f.seen[k] = e
		return false
	}
	if len(f.seen) >= f.max {
		f.sweep(now)
	}
	f.seen[k] = flowState{at: now}
	return true
}

// Allow는 csa가 이 연결을 들였다고 적는다.
func (f *flows) Allow(k flowKey) {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) >= f.max {
		f.sweep(now)
	}
	f.seen[k] = flowState{at: now, allowed: true}
}

// IsReply는 이 패킷이 앞서 들인 연결의 답인지 본다. 맞으면 그 연결의 시각을
// 새로 적는다. 오가는 동안 잊지 않게 하려는 것이다.
func (f *flows) IsReply(k flowKey) bool {
	now := time.Now()
	rev := k.reverse()
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.seen[rev]
	if !ok || !e.allowed || now.Sub(e.at) >= f.ttl {
		return false
	}
	e.at = now
	f.seen[rev] = e
	return true
}

// sweep은 오래된 것을 버린다. 자물쇠를 쥔 채로 부른다.
func (f *flows) sweep(now time.Time) {
	for k, e := range f.seen {
		if now.Sub(e.at) >= f.ttl {
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
