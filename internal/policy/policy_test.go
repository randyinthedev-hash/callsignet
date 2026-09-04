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
	if d := r.Inbound(addr("10.91.0.2"), 8080, netip.Addr{}); !d.Allow {
		t.Fatalf("허가된 상대를 막았다: %s", d.Reason)
	}
	// srv-c는 정책에 없다.
	if d := r.Inbound(addr("10.91.0.3"), 8080, netip.Addr{}); d.Allow {
		t.Fatal("정책에 없는 상대를 들였다")
	}
	// 열어 두지 않은 포트다.
	if d := r.Inbound(addr("10.91.0.2"), 9999, netip.Addr{}); d.Allow {
		t.Fatal("열어 두지 않은 포트를 들였다")
	}
	// 모르는 터널 IP다. 여기까지 오면 안 되지만 막아야 한다.
	if d := r.Inbound(addr("10.91.0.9"), 8080, netip.Addr{}); d.Allow {
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
	d := r.Inbound(addr("10.91.0.3"), 8080, netip.Addr{})
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
	if d := r.InboundICMP(addr("10.91.0.2"), netip.Addr{}); !d.Allow {
		t.Errorf("허가된 상대를 막았다: %s", d.Reason)
	}
	// srv-c와는 아무 권한이 없다.
	if d := r.OutboundICMP(addr("10.91.0.3")); d.Allow {
		t.Error("권한 없는 상대에게 나가게 했다")
	}
	if d := r.InboundICMP(addr("10.91.0.3"), netip.Addr{}); d.Allow {
		t.Error("권한 없는 상대를 들였다")
	}
	if d := r.InboundICMP(addr("10.91.0.9"), netip.Addr{}); d.Allow {
		t.Error("모르는 상대를 들였다")
	}
}

func TestPeerOf(t *testing.T) {
	r := rules(t)
	if id, ok := r.PeerOf(addr("10.91.0.2")); !ok || id != "srv-b" {
		t.Fatalf("srv-b여야 하는데 %s %v", id, ok)
	}
	if _, ok := r.PeerOf(addr("10.91.0.9")); ok {
		t.Fatal("모르는 터널 IP에 이름을 붙였다")
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

// 대역을 보는 규칙을 만든다. srv-b는 사무실 대역에서 올 때만 billing에 붙는다.
func bandRules(t *testing.T, cidrs []string, expires string) *Rules {
	t.Helper()
	c := &config.Config{
		Self: config.Self{PeerID: "srv-a"},
		Peers: []config.Peer{
			{PeerID: "srv-a", TunnelIP: "10.91.0.1",
				Services: []config.Service{{App: "billing", Port: 8080}}},
			{PeerID: "srv-b", TunnelIP: "10.91.0.2"},
			{PeerID: "srv-c", TunnelIP: "10.91.0.3"},
		},
		Policy: config.Policy{
			Inbound: []config.Inbound{{
				App: "billing", Allow: []string{"srv-b"},
				AllowCIDR: cidrs, Expires: expires,
			}},
		},
	}
	r, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestInboundChecksBand(t *testing.T) {
	r := bandRules(t, []string{"10.90.0.0/24"}, "2099-01-01")
	if !r.NeedsSource(8080) {
		t.Fatal("대역을 보는 규칙이면 출발지가 필요하다고 알려야 한다")
	}

	if d := r.Inbound(addr("10.91.0.2"), 8080, addr("10.90.0.7")); !d.Allow {
		t.Errorf("대역 안에서 온 것을 막았다: %s", d.Reason)
	}
	// 상대는 맞지만 대역 밖이다.
	d := r.Inbound(addr("10.91.0.2"), 8080, addr("192.0.2.7"))
	if d.Allow {
		t.Error("대역 밖에서 온 것을 들였다")
	}
	if !contains(d.Reason, "허용 대역 밖") || !contains(d.Reason, "192.0.2.7") {
		t.Errorf("무엇 때문에 막혔는지 적어야 하는데 %q", d.Reason)
	}
	// 출발지를 모르면 대역을 만족했다고 볼 수 없다.
	if d := r.Inbound(addr("10.91.0.2"), 8080, netip.Addr{}); d.Allow {
		t.Error("출발지를 모르는데 들였다")
	}
	// 대역 안이라도 상대가 다르면 막는다. 둘 다 만족해야 한다.
	if d := r.Inbound(addr("10.91.0.3"), 8080, addr("10.90.0.7")); d.Allow {
		t.Error("대역만 맞는 상대를 들였다")
	}
}

// 대역이 여럿이면 하나만 맞아도 된다.
func TestInboundChecksEveryBand(t *testing.T) {
	r := bandRules(t, []string{"10.90.0.0/24", "192.0.2.0/24"}, "2099-01-01")
	for _, from := range []string{"10.90.0.7", "192.0.2.7"} {
		if d := r.Inbound(addr("10.91.0.2"), 8080, addr(from)); !d.Allow {
			t.Errorf("대역 안인데 막았다: %s, %s", from, d.Reason)
		}
	}
	if d := r.Inbound(addr("10.91.0.2"), 8080, addr("203.0.113.7")); d.Allow {
		t.Error("어느 대역에도 없는데 들였다")
	}
}

// 기한이 지난 규칙은 죽는다. csa가 오래 도는 동안 기한이 지나갈 수 있으므로
// 설정을 읽을 때만 보지 않고 판단할 때마다 본다.
func TestExpiredRuleLetsNobodyIn(t *testing.T) {
	r := bandRules(t, []string{"10.90.0.0/24"}, "2020-01-01")
	d := r.Inbound(addr("10.91.0.2"), 8080, addr("10.90.0.7"))
	if d.Allow {
		t.Error("기한이 지난 규칙으로 들였다")
	}
	if !contains(d.Reason, "기한") {
		t.Errorf("기한 때문임을 적어야 하는데 %q", d.Reason)
	}
}

// 대역을 보지 않는 규칙만 있으면 wg에게 출발지를 묻지 않는다.
func TestNeedsSourceOnlyWhenBandExists(t *testing.T) {
	r := rules(t)
	if r.NeedsSource(8080) || r.NeedsSourceICMP() {
		t.Error("대역을 보는 규칙이 없는데 출발지를 묻는다")
	}
}

// ICMP에는 포트가 없다. 그 상대를 들이는 규칙에 대역이 걸려 있으면 대역도 본다.
func TestICMPChecksBand(t *testing.T) {
	r := bandRules(t, []string{"10.90.0.0/24"}, "2099-01-01")
	if !r.NeedsSourceICMP() {
		t.Fatal("대역을 보는 규칙이 있으면 ICMP에도 출발지가 필요하다")
	}
	if d := r.InboundICMP(addr("10.91.0.2"), addr("10.90.0.7")); !d.Allow {
		t.Errorf("대역 안에서 온 것을 막았다: %s", d.Reason)
	}
	if d := r.InboundICMP(addr("10.91.0.2"), addr("192.0.2.7")); d.Allow {
		t.Error("대역 밖에서 온 것을 들였다")
	}
}

// 앱 이름만 적고 조건을 하나도 적지 않은 규칙은 아무도 들이지 않는다.
func TestRuleWithNoConditionLetsNobodyIn(t *testing.T) {
	c := &config.Config{
		Self: config.Self{PeerID: "srv-a"},
		Peers: []config.Peer{
			{PeerID: "srv-a", TunnelIP: "10.91.0.1",
				Services: []config.Service{{App: "billing", Port: 8080}}},
			{PeerID: "srv-b", TunnelIP: "10.91.0.2"},
		},
		Policy: config.Policy{Inbound: []config.Inbound{{App: "billing"}}},
	}
	r, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if d := r.Inbound(addr("10.91.0.2"), 8080, addr("10.90.0.7")); d.Allow {
		t.Error("조건 없는 규칙으로 들였다")
	}
}

// 한 앱에 규칙이 여럿이면 하나만 만족해도 들인다.
func TestSeveralRulesForOneApp(t *testing.T) {
	c := &config.Config{
		Self: config.Self{PeerID: "srv-a"},
		Peers: []config.Peer{
			{PeerID: "srv-a", TunnelIP: "10.91.0.1",
				Services: []config.Service{{App: "billing", Port: 8080}}},
			{PeerID: "srv-b", TunnelIP: "10.91.0.2"},
			{PeerID: "srv-c", TunnelIP: "10.91.0.3"},
		},
		Policy: config.Policy{Inbound: []config.Inbound{
			{App: "billing", Allow: []string{"srv-b"}},
			{App: "billing", Allow: []string{"srv-c"},
				AllowCIDR: []string{"10.90.0.0/24"}, Expires: "2099-01-01"},
		}},
	}
	r, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	// srv-b는 대역을 가리지 않는 규칙으로 들어온다.
	if d := r.Inbound(addr("10.91.0.2"), 8080, addr("203.0.113.7")); !d.Allow {
		t.Errorf("대역을 가리지 않는 규칙이 있는데 막았다: %s", d.Reason)
	}
	// srv-c는 대역을 만족해야 들어온다.
	if d := r.Inbound(addr("10.91.0.3"), 8080, addr("10.90.0.7")); !d.Allow {
		t.Errorf("대역 안인데 막았다: %s", d.Reason)
	}
	if d := r.Inbound(addr("10.91.0.3"), 8080, addr("203.0.113.7")); d.Allow {
		t.Error("대역 밖인데 들였다")
	}
}

func TestNewRejectsBadCIDR(t *testing.T) {
	c := &config.Config{
		Self: config.Self{PeerID: "srv-a"},
		Peers: []config.Peer{{PeerID: "srv-a", TunnelIP: "10.91.0.1",
			Services: []config.Service{{App: "billing", Port: 8080}}}},
		Policy: config.Policy{Inbound: []config.Inbound{
			{App: "billing", AllowCIDR: []string{"10.90.0.0/99"}, Expires: "2099-01-01"},
		}},
	}
	if _, err := New(c); err == nil {
		t.Error("읽을 수 없는 대역을 받아들였다")
	}
	c.Policy.Inbound[0].AllowCIDR = []string{"10.90.0.0/24"}
	c.Policy.Inbound[0].Expires = "언젠가"
	if _, err := New(c); err == nil {
		t.Error("읽을 수 없는 기한을 받아들였다")
	}
}
