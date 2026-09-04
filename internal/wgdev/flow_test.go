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
	f := newFlows(connTTL, connMax)
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
