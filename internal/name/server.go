package name

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DefaultTTL은 답에 붙이는 수명이다. 터널 IP는 거의 바뀌지 않으므로 짧게 둘
// 이유가 없다.
const DefaultTTL = 300

// Server는 csa가 여는 이름 해석기다. 내부 도메인과 그 역방향 구역만 답한다.
type Server struct {
	// table은 csa reload가 통째로 갈아 끼운다.
	table   atomic.Pointer[Table]
	ttl     uint32
	logf    func(string, ...any)
	servers []*dns.Server
}

// NewServer는 표를 받아 서버를 만든다. 아직 열지는 않는다.
func NewServer(t *Table, ttl int, logf func(string, ...any)) *Server {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	s := &Server{ttl: uint32(ttl), logf: logf}
	s.table.Store(t)
	return s
}

// Start는 주어진 주소들에서 UDP와 TCP로 질의를 받기 시작한다.
//
// 루프백 주소와 터널 IP 둘 다에서 받는다. /etc/resolv.conf에는 포트를 적을 수
// 없어 루프백 주소가 필요하고, systemd-resolved는 루프백 주소를 받아 주지 않아
// 터널 IP가 필요하다.
func (s *Server) Start(listens ...string) error {
	for _, l := range listens {
		if l == "" {
			continue
		}
		if err := s.startOne(l); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) startOne(listen string) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	udp := &dns.Server{Addr: listen, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: listen, Net: "tcp", Handler: mux}
	s.servers = append(s.servers, udp, tcp)

	ready := make(chan error, 2)
	udp.NotifyStartedFunc = func() { ready <- nil }
	go func() {
		if err := udp.ListenAndServe(); err != nil {
			ready <- fmt.Errorf("이름 해석기를 열지 못했다: %s: %w", listen, err)
		}
	}()
	go func() {
		if err := tcp.ListenAndServe(); err != nil {
			s.logf("이름 해석기 TCP를 열지 못했습니다: %s: %v", listen, err)
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			return err
		}
	case <-time.After(3 * time.Second):
		return fmt.Errorf("이름 해석기가 시작되지 않았다: %s", listen)
	}
	s.logf("이름 해석기를 열었습니다. 주소는 %s이고 도메인은 %s입니다.", listen, s.table.Load().Domain)
	return nil
}

// note는 질의와 답을 적는다. 어떤 이름이 무엇으로 풀렸는지 남겨야, 앱이 상대를
// 찾지 못할 때 어디서 막혔는지 운영자가 알 수 있다.
func (s *Server) note(q dns.Question, m *dns.Msg) {
	s.logf("이름 질의에 답했습니다. 이름 %s, 종류 %s, 답 %s",
		strings.TrimSuffix(q.Name, "."), dns.TypeToString[q.Qtype], answerOf(m))
}

// answerOf는 답을 한 줄로 적는다. 거절하거나 없다고 답한 것도 그대로 적는다.
func answerOf(m *dns.Msg) string {
	if m.Rcode != dns.RcodeSuccess {
		return dns.RcodeToString[m.Rcode]
	}
	var out []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.PTR:
			out = append(out, strings.TrimSuffix(v.Ptr, "."))
		}
	}
	if len(out) == 0 {
		return "없음"
	}
	return strings.Join(out, ", ")
}

// SetTable은 이름 표를 갈아 끼운다. csa reload가 쓴다. 이미 열려 있는 리슨
// 주소는 그대로 두고 답하는 내용만 바꾼다.
func (s *Server) SetTable(t *Table) {
	s.table.Store(t)
}

// Close는 서버를 닫는다.
func (s *Server) Close() {
	for _, srv := range s.servers {
		srv.Shutdown()
	}
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) != 1 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	defer func() { s.note(q, m) }()
	t := s.table.Load()
	switch q.Qtype {
	case dns.TypeA:
		s.answerA(t, m, q)
	case dns.TypePTR:
		s.answerPTR(t, m, q)
	case dns.TypeAAAA:
		// 이름은 있으나 IPv6 주소가 없다. 없는 이름과 구별해야 한다.
		if _, ok := t.Forward(q.Name); !ok {
			m.SetRcode(r, dns.RcodeNameError)
		}
	default:
		if !t.InDomain(q.Name) {
			m.SetRcode(r, dns.RcodeRefused)
		}
	}
	w.WriteMsg(m)
}

func (s *Server) answerA(t *Table, m *dns.Msg, q dns.Question) {
	if !t.InDomain(q.Name) {
		// 우리 도메인이 아니면 답할 자격이 없다.
		m.Rcode = dns.RcodeRefused
		return
	}
	ip, ok := t.Forward(q.Name)
	if !ok || !ip.Is4() {
		m.Rcode = dns.RcodeNameError
		return
	}
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl},
		A:   net.IP(ip.AsSlice()),
	})
}

func (s *Server) answerPTR(t *Table, m *dns.Msg, q dns.Question) {
	ip, ok := ptrToAddr(q.Name)
	if !ok {
		m.Rcode = dns.RcodeRefused
		return
	}
	machine, ok := t.Reverse(ip)
	if !ok {
		m.Rcode = dns.RcodeNameError
		return
	}
	m.Answer = append(m.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: s.ttl},
		Ptr: dns.Fqdn(machine),
	})
}

// ptrToAddr은 7.0.91.10.in-addr.arpa 같은 이름을 10.91.0.7로 되돌린다.
func ptrToAddr(name string) (netip.Addr, bool) {
	n := strings.ToLower(strings.TrimSuffix(dns.Fqdn(name), "."))
	const suffix = ".in-addr.arpa"
	if !strings.HasSuffix(n, suffix) {
		return netip.Addr{}, false
	}
	parts := strings.Split(strings.TrimSuffix(n, suffix), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	addr, err := netip.ParseAddr(strings.Join(parts, "."))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// ReverseZone은 터널 대역에 해당하는 역방향 구역 이름을 돌려준다.
// 운영자나 csa가 리졸버에 등록할 때 쓴다.
func ReverseZone(cidr netip.Prefix) (string, error) {
	if !cidr.Addr().Is4() {
		return "", fmt.Errorf("IPv4 대역만 다룬다: %s", cidr)
	}
	bits := cidr.Bits()
	if bits%8 != 0 || bits == 0 {
		return "", fmt.Errorf("역방향 구역은 8비트 단위여야 한다: %s", cidr)
	}
	b := cidr.Addr().As4()
	var parts []string
	for i := bits/8 - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprint(b[i]))
	}
	return strings.Join(parts, ".") + ".in-addr.arpa", nil
}
