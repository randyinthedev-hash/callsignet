package name

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DefaultTTL은 답에 붙이는 수명이다. 터널 IP는 거의 바뀌지 않으므로 짧게 둘
// 이유가 없다.
const DefaultTTL = 300

// Server는 csa가 여는 이름 해석기다. 내부 도메인과 그 역방향 구역만 답한다.
type Server struct {
	table *Table
	ttl   uint32
	logf  func(string, ...any)
	udp   *dns.Server
	tcp   *dns.Server
}

// NewServer는 표를 받아 서버를 만든다. 아직 열지는 않는다.
func NewServer(t *Table, ttl int, logf func(string, ...any)) *Server {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Server{table: t, ttl: uint32(ttl), logf: logf}
}

// Start는 주어진 주소에서 UDP와 TCP로 질의를 받기 시작한다.
func (s *Server) Start(listen string) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.udp = &dns.Server{Addr: listen, Net: "udp", Handler: mux}
	s.tcp = &dns.Server{Addr: listen, Net: "tcp", Handler: mux}

	ready := make(chan error, 2)
	s.udp.NotifyStartedFunc = func() { ready <- nil }
	go func() {
		if err := s.udp.ListenAndServe(); err != nil {
			ready <- fmt.Errorf("이름 해석기를 열지 못했다: %w", err)
		}
	}()
	go func() {
		if err := s.tcp.ListenAndServe(); err != nil {
			s.logf("이름 해석기 TCP를 열지 못했습니다: %v", err)
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
	s.logf("이름 해석기를 열었습니다. 주소는 %s이고 도메인은 %s입니다.", listen, s.table.Domain)
	return nil
}

// Close는 서버를 닫는다.
func (s *Server) Close() {
	if s.udp != nil {
		s.udp.Shutdown()
	}
	if s.tcp != nil {
		s.tcp.Shutdown()
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
	switch q.Qtype {
	case dns.TypeA:
		s.answerA(m, q)
	case dns.TypePTR:
		s.answerPTR(m, q)
	case dns.TypeAAAA:
		// 이름은 있으나 IPv6 주소가 없다. 없는 이름과 구별해야 한다.
		if _, ok := s.table.Forward(q.Name); !ok {
			m.SetRcode(r, dns.RcodeNameError)
		}
	default:
		if !s.table.InDomain(q.Name) {
			m.SetRcode(r, dns.RcodeRefused)
		}
	}
	w.WriteMsg(m)
}

func (s *Server) answerA(m *dns.Msg, q dns.Question) {
	if !s.table.InDomain(q.Name) {
		// 우리 도메인이 아니면 답할 자격이 없다.
		m.Rcode = dns.RcodeRefused
		return
	}
	ip, ok := s.table.Forward(q.Name)
	if !ok || !ip.Is4() {
		m.Rcode = dns.RcodeNameError
		return
	}
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl},
		A:   net.IP(ip.AsSlice()),
	})
}

func (s *Server) answerPTR(m *dns.Msg, q dns.Question) {
	ip, ok := ptrToAddr(q.Name)
	if !ok {
		m.Rcode = dns.RcodeRefused
		return
	}
	machine, ok := s.table.Reverse(ip)
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
