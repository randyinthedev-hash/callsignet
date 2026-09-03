package name

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestPtrToAddr(t *testing.T) {
	got, ok := ptrToAddr("7.0.91.10.in-addr.arpa.")
	if !ok || got.String() != "10.91.0.7" {
		t.Fatalf("10.91.0.7이어야 하는데 %v %v", got, ok)
	}
	for _, bad := range []string{"example.com.", "1.2.3.in-addr.arpa.", "a.b.c.d.in-addr.arpa."} {
		if _, ok := ptrToAddr(bad); ok {
			t.Errorf("%s를 주소로 읽으면 안 된다", bad)
		}
	}
}

func TestReverseZone(t *testing.T) {
	cases := map[string]string{
		"10.91.0.0/24": "0.91.10.in-addr.arpa",
		"10.91.0.0/16": "91.10.in-addr.arpa",
		"10.0.0.0/8":   "10.in-addr.arpa",
	}
	for cidr, want := range cases {
		got, err := ReverseZone(netip.MustParsePrefix(cidr))
		if err != nil || got != want {
			t.Errorf("%s는 %s여야 하는데 %s (%v)", cidr, want, got, err)
		}
	}
	if _, err := ReverseZone(netip.MustParsePrefix("10.91.0.0/25")); err == nil {
		t.Error("8비트 단위가 아닌 대역을 받아들였다")
	}
}

// ask는 서버 처리기를 직접 불러 답을 받는다. 소켓을 열지 않으므로 root가 필요 없다.
func ask(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	s := NewServer(table(t), 0, func(string, ...any) {})
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	w := &capture{}
	s.handle(w, req)
	if w.msg == nil {
		t.Fatal("답이 없다")
	}
	return w.msg
}

func TestServerAnswersA(t *testing.T) {
	m := ask(t, "report.srv-b.cs.example.internal", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("답이 하나여야 하는데 %v", m)
	}
	a, ok := m.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.91.0.2" {
		t.Fatalf("10.91.0.2여야 하는데 %v", m.Answer[0])
	}
	if a.Hdr.Ttl != DefaultTTL {
		t.Fatalf("수명이 %d여야 하는데 %d", DefaultTTL, a.Hdr.Ttl)
	}
}

func TestServerAnswersPTR(t *testing.T) {
	m := ask(t, "2.0.91.10.in-addr.arpa", dns.TypePTR)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("답이 하나여야 하는데 %v", m)
	}
	p := m.Answer[0].(*dns.PTR)
	if p.Ptr != "srv-b.cs.example.internal." {
		t.Fatalf("머신 이름이어야 하는데 %s", p.Ptr)
	}
}

func TestServerRefusesOutsideDomain(t *testing.T) {
	if m := ask(t, "www.example.com", dns.TypeA); m.Rcode != dns.RcodeRefused {
		t.Fatalf("남의 도메인은 거절해야 하는데 %s", dns.RcodeToString[m.Rcode])
	}
}

func TestServerSaysNoSuchName(t *testing.T) {
	if m := ask(t, "srv-z.cs.example.internal", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Fatalf("없는 이름이어야 하는데 %s", dns.RcodeToString[m.Rcode])
	}
	if m := ask(t, "9.0.91.10.in-addr.arpa", dns.TypePTR); m.Rcode != dns.RcodeNameError {
		t.Fatalf("모르는 터널 IP여야 하는데 %s", dns.RcodeToString[m.Rcode])
	}
}

func TestServerAAAAIsEmptyNotMissing(t *testing.T) {
	// 이름은 있으나 IPv6 주소가 없다. 없는 이름과 구별해야 한다.
	m := ask(t, "srv-b.cs.example.internal", dns.TypeAAAA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Fatalf("있는 이름의 빈 답이어야 하는데 %v", m)
	}
	if m := ask(t, "srv-z.cs.example.internal", dns.TypeAAAA); m.Rcode != dns.RcodeNameError {
		t.Fatalf("없는 이름이어야 하는데 %s", dns.RcodeToString[m.Rcode])
	}
}

type capture struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (c *capture) WriteMsg(m *dns.Msg) error { c.msg = m; return nil }
