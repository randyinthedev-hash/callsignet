package policy

import (
	"net/netip"
	"testing"

	"github.com/randyinthedev-hash/callsignet/internal/config"
)

func rules(t *testing.T) *Rules {
	t.Helper()
	c := &config.Config{
		Self: config.Self{PeerID: "srv-a"},
		Peers: []config.Peer{
			{PeerID: "srv-a", TunnelIP: "10.91.0.1",
				Services: []config.Service{{App: "billing", Port: 8080}}},
			{PeerID: "srv-b", TunnelIP: "10.91.0.2",
				Services: []config.Service{{App: "report", Port: 9090}}},
			{PeerID: "srv-c", TunnelIP: "10.91.0.3",
				Services: []config.Service{{App: "batch", Port: 7070}}},
		},
		Policy: config.Policy{
			Inbound:  []config.Inbound{{App: "billing", Allow: []string{"srv-b"}}},
			Outbound: []string{"srv-b/report"},
		},
	}
	r, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestInbound(t *testing.T) {
	r := rules(t)
	if d := r.Inbound(addr("10.91.0.2"), 8080); !d.Allow {
		t.Fatalf("허가된 상대를 막았다: %s", d.Reason)
	}
	// srv-c는 정책에 없다.
	if d := r.Inbound(addr("10.91.0.3"), 8080); d.Allow {
		t.Fatal("정책에 없는 상대를 들였다")
	}
	// 열어 두지 않은 포트다.
	if d := r.Inbound(addr("10.91.0.2"), 9999); d.Allow {
		t.Fatal("열어 두지 않은 포트를 들였다")
	}
	// 모르는 터널 IP다. 여기까지 오면 안 되지만 막아야 한다.
	if d := r.Inbound(addr("10.91.0.9"), 8080); d.Allow {
		t.Fatal("모르는 상대를 들였다")
	}
}

func TestOutbound(t *testing.T) {
	r := rules(t)
	if d := r.Outbound(addr("10.91.0.2"), 9090); !d.Allow {
		t.Fatalf("허가된 곳을 막았다: %s", d.Reason)
	}
	// 같은 상대라도 정책에 없는 포트다.
	if d := r.Outbound(addr("10.91.0.2"), 8080); d.Allow {
		t.Fatal("정책에 없는 포트로 나가게 했다")
	}
	// 정책에 없는 상대다.
	if d := r.Outbound(addr("10.91.0.3"), 7070); d.Allow {
		t.Fatal("정책에 없는 상대에게 나가게 했다")
	}
	if d := r.Outbound(addr("10.91.0.9"), 80); d.Allow {
		t.Fatal("모르는 상대에게 나가게 했다")
	}
}

func TestReasonNamesThePeer(t *testing.T) {
	r := rules(t)
	d := r.Inbound(addr("10.91.0.3"), 8080)
	if d.Reason == "" {
		t.Fatal("까닭이 없다")
	}
	// 기록을 읽는 사람이 누구인지 알아야 한다.
	if want := "srv-c"; !contains(d.Reason, want) {
		t.Fatalf("%q가 까닭에 있어야 하는데 %q", want, d.Reason)
	}
}

func TestICMPFollowsPolicy(t *testing.T) {
	r := rules(t)
	// srv-b와는 서로 통신할 권한이 있으므로 진단도 된다.
	if d := r.OutboundICMP(addr("10.91.0.2")); !d.Allow {
		t.Errorf("허가된 상대에게 막았다: %s", d.Reason)
	}
	if d := r.InboundICMP(addr("10.91.0.2")); !d.Allow {
		t.Errorf("허가된 상대를 막았다: %s", d.Reason)
	}
	// srv-c와는 아무 권한이 없다.
	if d := r.OutboundICMP(addr("10.91.0.3")); d.Allow {
		t.Error("권한 없는 상대에게 나가게 했다")
	}
	if d := r.InboundICMP(addr("10.91.0.3")); d.Allow {
		t.Error("권한 없는 상대를 들였다")
	}
	if d := r.InboundICMP(addr("10.91.0.9")); d.Allow {
		t.Error("모르는 상대를 들였다")
	}
}

func TestPeerOfAndSelfIP(t *testing.T) {
	r := rules(t)
	if id, ok := r.PeerOf(addr("10.91.0.2")); !ok || id != "srv-b" {
		t.Fatalf("srv-b여야 하는데 %s %v", id, ok)
	}
	if _, ok := r.PeerOf(addr("10.91.0.9")); ok {
		t.Fatal("모르는 터널 IP에 이름을 붙였다")
	}
	if r.SelfIP() != addr("10.91.0.1") {
		t.Fatalf("이 머신의 터널 IP가 틀렸다: %s", r.SelfIP())
	}
}

func TestNewRejectsBadPolicy(t *testing.T) {
	base := func() *config.Config {
		return &config.Config{
			Self:  config.Self{PeerID: "srv-a"},
			Peers: []config.Peer{{PeerID: "srv-a", TunnelIP: "10.91.0.1"}},
		}
	}
	c := base()
	c.Policy.Inbound = []config.Inbound{{App: "없음", Allow: []string{"srv-a"}}}
	if _, err := New(c); err == nil {
		t.Error("이 머신에 없는 app을 받아들였다")
	}
	c = base()
	c.Policy.Outbound = []string{"srv-a"}
	if _, err := New(c); err == nil {
		t.Error("peer-id/app 형태가 아닌 것을 받아들였다")
	}
	c = base()
	c.Policy.Outbound = []string{"srv-z/x"}
	if _, err := New(c); err == nil {
		t.Error("없는 상대를 받아들였다")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
