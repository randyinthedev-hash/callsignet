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
	f := newFlows()
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
	f := newFlows()
	f.ttl = 10 * time.Millisecond
	f.First(key(40000))
	time.Sleep(20 * time.Millisecond)
	if !f.First(key(40000)) {
		t.Fatal("오래된 연결을 다시 처음으로 보지 않았다")
	}
}

func TestFlowsDoNotGrowForever(t *testing.T) {
	f := newFlows()
	f.max = 100
	for i := 0; i < 500; i++ {
		f.First(key(uint16(40000 + i)))
	}
	if len(f.seen) > f.max {
		t.Fatalf("기억이 %d개까지 늘었다", len(f.seen))
	}
}
