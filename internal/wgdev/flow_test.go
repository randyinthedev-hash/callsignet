//go:build linux

package wgdev

import (
	"net/netip"
	"testing"
	"time"
)

func key(sport uint16) flowKey {
	return flowKey{
		src:   netip.MustParseAddr("10.91.0.2"),
		dst:   netip.MustParseAddr("10.91.0.1"),
		sport: sport, dport: 8080, proto: 6,
	}
}

func TestFirstOnlyOncePerFlow(t *testing.T) {
	f := newFlows(logTTL, logMax)
	if !f.First(key(40000)) {
		t.Fatal("처음 본 연결인데 아니라고 했다")
	}
	for i := 0; i < 5; i++ {
		if f.First(key(40000)) {
			t.Fatal("같은 연결을 다시 처음이라고 했다")
		}
	}
	if !f.First(key(40001)) {
		t.Fatal("다른 연결을 처음이 아니라고 했다")
	}
}

func TestFirstAgainAfterTTL(t *testing.T) {
	f := newFlows(10*time.Millisecond, logMax)
	f.First(key(40000))
	time.Sleep(20 * time.Millisecond)
	if !f.First(key(40000)) {
		t.Fatal("오래된 연결을 다시 처음으로 보지 않았다")
	}
}

func TestFlowsDoNotGrowForever(t *testing.T) {
	f := newFlows(logTTL, 100)
	for i := 0; i < 500; i++ {
		f.First(key(uint16(40000 + i)))
	}
	if len(f.seen) > f.max {
		t.Fatalf("기억이 %d개까지 늘었다", len(f.seen))
	}
}

// 되돌아오는 패킷을 알아보아야 한다. 정책은 연결을 여는 쪽만 보므로, 답을
// 알아보지 못하면 TCP가 서지 않는다.
func TestReplyOfAllowedFlow(t *testing.T) {
	f := newConns(connMax)
	out := key(40000) // 10.91.0.2:40000 -> 10.91.0.1:8080
	back := out.reverse()

	// 아직 들인 것이 없으면 답도 아니다.
	if f.IsReply(back) {
		t.Fatal("들인 적 없는 연결의 답이라고 했다")
	}
	// 처음 본 것만으로는 들인 것이 아니다. 막힌 연결도 First가 기억한다.
	f.First(out)
	if f.IsReply(back) {
		t.Fatal("들이지 않은 연결의 답을 들이려 한다")
	}

	f.Allow(out)
	if !f.IsReply(back) {
		t.Fatal("들인 연결의 답을 알아보지 못했다")
	}
	// 같은 방향의 패킷은 답이 아니다.
	if f.IsReply(out) {
		t.Fatal("같은 방향을 답이라고 했다")
	}
	// 다른 연결의 답도 아니다.
	if f.IsReply(key(40001).reverse()) {
		t.Fatal("다른 연결의 답을 들이려 한다")
	}
}

func TestReplyForgottenAfterTTL(t *testing.T) {
	f := newFlows(10*time.Millisecond, connMax)
	out := key(40000)
	f.Allow(out)
	time.Sleep(20 * time.Millisecond)
	if f.IsReply(out.reverse()) {
		t.Fatal("오래 쉰 연결을 기억하고 있다")
	}
}

// 오가는 동안에는 잊지 않아야 한다. 답을 볼 때마다 시각을 새로 적는다.
func TestReplyKeepsFlowAlive(t *testing.T) {
	f := newFlows(30*time.Millisecond, connMax)
	out := key(40000)
	f.Allow(out)
	for i := 0; i < 5; i++ {
		time.Sleep(10 * time.Millisecond)
		if !f.IsReply(out.reverse()) {
			t.Fatalf("오가는 중인데 잊었다: %d번째", i+1)
		}
	}
}

// UDP와 ICMP는 연결이 없다. TCP만큼 오래 기억하면 요청 하나가 그동안 되돌아오는
// 패킷을 모두 들이게 된다.
func TestConnTTLDependsOnProtocol(t *testing.T) {
	if connTTL(protoTCP) <= connTTL(protoUDP) {
		t.Error("TCP를 UDP보다 오래 기억해야 한다")
	}
	if connTTL(protoUDP) <= connTTL(1) {
		t.Error("UDP를 ICMP보다 오래 기억해야 한다")
	}
}

func TestConnsUsesProtocolTTL(t *testing.T) {
	f := newConns(connMax)
	udp := key(40000)
	udp.proto = protoUDP
	f.Allow(udp)
	if !f.IsReply(udp.reverse()) {
		t.Fatal("방금 들인 연결의 답을 알아보지 못했다")
	}
	// 시각을 UDP 수명보다 앞으로 돌린다. TCP 수명 안이지만 UDP는 지났다.
	f.mu.Lock()
	e := f.seen[udp]
	e.at = time.Now().Add(-connTTL(protoUDP) - time.Second)
	f.seen[udp] = e
	f.mu.Unlock()
	if f.IsReply(udp.reverse()) {
		t.Error("UDP를 TCP만큼 오래 기억한다")
	}
}

// 정책이 바뀌면 들여 둔 기억 가운데 허가되지 않는 것을 잊어야 한다. 그러지
// 않으면 철회한 뒤에도 그 연결의 되돌아오는 패킷이 정책을 다시 보지 않고 지난다.
func TestForgetDropsRevoked(t *testing.T) {
	f := newConns(connMax)
	keep := key(40000)
	drop := key(40001)
	f.Allow(keep)
	f.Allow(drop)

	n := f.Forget(func(k flowKey) bool { return k.sport != 40001 })
	if n != 1 {
		t.Fatalf("하나를 잊어야 하는데 %d개", n)
	}
	if !f.IsReply(keep.reverse()) {
		t.Error("허가된 연결까지 잊었다")
	}
	if f.IsReply(drop.reverse()) {
		t.Error("허가되지 않은 연결을 그대로 두었다")
	}
}

// 들이지 않은 기억은 Forget이 건드리지 않는다. 그것은 기록용이지 들인 표시가 아니다.
func TestForgetLeavesUnadmitted(t *testing.T) {
	f := newConns(connMax)
	k := key(40000)
	f.First(k) // 처음 보았다고만 적는다. 들인 것이 아니다
	if n := f.Forget(func(flowKey) bool { return false }); n != 0 {
		t.Errorf("들이지 않은 것을 셌다: %d개", n)
	}
}
