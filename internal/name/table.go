// Package name은 csa가 답하는 이름 표를 다룬다.
package name

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/randyinthedev-hash/callsignet/internal/config"
)

// Table은 이름과 터널 IP의 대응이다. csa는 설정에 있는 것만 답한다.
type Table struct {
	Domain  string
	forward map[string]netip.Addr // 이름 → 터널 IP
	reverse map[netip.Addr]string // 터널 IP → 머신 이름
}

// NewTable은 설정에서 이름 표를 만든다.
//
// 정방향은 두 가지를 답한다. 서비스 이름 app.peer-id.도메인과 머신 이름
// peer-id.도메인이다. 둘 다 그 머신의 터널 IP를 가리킨다.
//
// 역방향은 머신 이름만 답한다. 한 머신에 앱이 여럿이면 서비스 이름도 여럿인데
// 터널 IP는 하나뿐이라 그중 하나를 고를 수 없기 때문이다.
func NewTable(c *config.Config) (*Table, error) {
	domain := strings.Trim(strings.ToLower(c.Self.Domain), ".")
	if domain == "" {
		return nil, fmt.Errorf("csa.toml에 domain이 없다")
	}
	t := &Table{
		Domain:  domain,
		forward: map[string]netip.Addr{},
		reverse: map[netip.Addr]string{},
	}
	for _, peer := range c.Peers {
		ip, err := netip.ParseAddr(peer.TunnelIP)
		if err != nil {
			return nil, fmt.Errorf("터널 IP를 읽을 수 없다: %s의 %s", peer.PeerID, peer.TunnelIP)
		}
		machine := strings.ToLower(peer.PeerID) + "." + domain
		t.forward[machine] = ip
		t.reverse[ip] = machine
		for _, svc := range peer.Services {
			t.forward[strings.ToLower(svc.App)+"."+machine] = ip
		}
	}
	return t, nil
}

// Forward는 이름을 터널 IP로 바꾼다. 설정에 없는 이름에는 답하지 않는다.
func (t *Table) Forward(name string) (netip.Addr, bool) {
	ip, ok := t.forward[normalize(name)]
	return ip, ok
}

// Reverse는 터널 IP를 머신 이름으로 바꾼다.
func (t *Table) Reverse(ip netip.Addr) (string, bool) {
	n, ok := t.reverse[ip.Unmap()]
	return n, ok
}

// InDomain은 그 이름이 우리 내부 도메인에 속하는지 본다.
func (t *Table) InDomain(name string) bool {
	n := normalize(name)
	return n == t.Domain || strings.HasSuffix(n, "."+t.Domain)
}

// Names는 표에 있는 이름을 모두 돌려준다. 확인에 쓴다.
func (t *Table) Names() []string {
	out := make([]string, 0, len(t.forward))
	for n := range t.forward {
		out = append(out, n)
	}
	return out
}

func normalize(name string) string {
	return strings.Trim(strings.ToLower(name), ".")
}
