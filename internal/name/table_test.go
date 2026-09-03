package name

import (
	"net/netip"
	"testing"

	"github.com/randyinthedev-hash/callsignet/internal/config"
)

func table(t *testing.T) *Table {
	t.Helper()
	c := &config.Config{
		Self: config.Self{PeerID: "srv-a", Domain: "cs.example.internal"},
		Peers: []config.Peer{
			{PeerID: "srv-a", TunnelIP: "10.91.0.1",
				Services: []config.Service{{App: "billing", Port: 8080}}},
			{PeerID: "srv-b", TunnelIP: "10.91.0.2",
				Services: []config.Service{{App: "report", Port: 8080}, {App: "batch", Port: 9090}}},
		},
	}
	tab, err := NewTable(c)
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestForward(t *testing.T) {
	tab := table(t)
	cases := map[string]string{
		"report.srv-b.cs.example.internal": "10.91.0.2",
		"batch.srv-b.cs.example.internal":  "10.91.0.2",
		"srv-b.cs.example.internal":        "10.91.0.2",
		"billing.srv-a.cs.example.internal": "10.91.0.1",
		"srv-a.cs.example.internal":         "10.91.0.1",
		// 대소문자와 끝점은 가리지 않는다.
		"REPORT.SRV-B.CS.EXAMPLE.INTERNAL.": "10.91.0.2",
	}
	for name, want := range cases {
		got, ok := tab.Forward(name)
		if !ok {
			t.Errorf("%s를 답하지 못했다", name)
			continue
		}
		if got.String() != want {
			t.Errorf("%s는 %s여야 하는데 %s", name, want, got)
		}
	}
}

func TestForwardRefusesUnknown(t *testing.T) {
	tab := table(t)
	for _, name := range []string{
		"srv-z.cs.example.internal",         // 없는 머신
		"없는앱.srv-b.cs.example.internal",   // 없는 앱
		"report.srv-a.cs.example.internal",  // 다른 머신의 앱
		"cs.example.internal",               // 도메인 자체
		"www.example.com",                   // 우리 도메인이 아니다
	} {
		if _, ok := tab.Forward(name); ok {
			t.Errorf("%s에 답하면 안 된다", name)
		}
	}
}

func TestReverse(t *testing.T) {
	tab := table(t)
	got, ok := tab.Reverse(netip.MustParseAddr("10.91.0.2"))
	if !ok {
		t.Fatal("역방향을 답하지 못했다")
	}
	// 역방향은 머신 이름을 답한다. 서비스 이름 가운데 하나를 고르지 않는다.
	if got != "srv-b.cs.example.internal" {
		t.Fatalf("머신 이름이어야 하는데 %s", got)
	}
	if _, ok := tab.Reverse(netip.MustParseAddr("10.91.0.9")); ok {
		t.Fatal("모르는 터널 IP에 답하면 안 된다")
	}
}

func TestReverseAndForwardMatch(t *testing.T) {
	tab := table(t)
	ip := netip.MustParseAddr("10.91.0.2")
	machine, ok := tab.Reverse(ip)
	if !ok {
		t.Fatal("역방향을 답하지 못했다")
	}
	// 역방향이 답한 이름은 정방향으로 다시 풀려야 한다.
	back, ok := tab.Forward(machine)
	if !ok || back != ip {
		t.Fatalf("%s를 정방향으로 다시 풀지 못했다", machine)
	}
}

func TestInDomain(t *testing.T) {
	tab := table(t)
	if !tab.InDomain("srv-b.cs.example.internal") || !tab.InDomain("cs.example.internal") {
		t.Error("우리 도메인을 알아보지 못했다")
	}
	if tab.InDomain("www.example.com") || tab.InDomain("cs.example.internal.evil.com") {
		t.Error("남의 도메인을 우리 것으로 보았다")
	}
}
