// Package nat은 실제 IP와 터널 IP를 서로 바꾸는 nftables 표를 건다.
//
// 앱은 상대를 지금 쓰는 실제 IP로 부르고, 두 csa 사이에서 안쪽 패킷은 터널
// IP를 쓴다. 그 사이를 잇는 것이 이 표다. 보내는 쪽에서는 상대의 실제 IP와
// 서비스 포트로 가는 패킷의 목적지를 상대의 터널 IP로, 출발지를 이 머신의 터널
// IP로 바꾼다. 받는 쪽에서는 터널로 들어온 패킷의 목적지를 이 머신의 실제 IP로,
// 출발지를 상대의 실제 IP로 바꾼다. 되돌아가는 패킷은 커널의 연결 추적이
// 되돌린다.
//
// csa는 주소를 자기가 바꾸지 않고 커널에 맡긴다. 목적지와 출발지를 한 자리에서
// 바꿔야 연결 추적이 흐름을 하나로 보기 때문이다. 표는 직통 경로를 닫는 표와
// 따로 둔다. inet 표의 NAT 체인은 커널 5.2부터 되는데 그보다 오래된 커널이 아직
// 있고, 터널 IP는 IPv4만 다루므로 ip 표로 충분하다.
package nat

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"

	"github.com/randyinthedev-hash/callsignet/internal/nft"
)

const (
	tableName        = "callsignet-nat"
	steeredCounter   = "steered"
	presentedCounter = "presented"
)

// Outgoing은 앱이 상대의 실제 IP로 부른 연결을 터널로 돌릴지 정한다.
type Outgoing int

const (
	// OutServices는 peers.toml에 적힌 상대의 서비스 포트로 가는 연결을 돌린다. 기본값이다.
	OutServices Outgoing = iota
	// OutOff는 돌리지 않는다.
	OutOff
)

func (o Outgoing) String() string {
	if o == OutOff {
		return "돌리지 않음"
	}
	return "서비스 포트로 가는 연결을 터널로 돌림"
}

// ParseOutgoing은 csa.toml의 nat.outgoing을 읽는다. 빈 값은 기본값이다.
func ParseOutgoing(s string) (Outgoing, error) {
	switch s {
	case "", "services":
		return OutServices, nil
	case "off":
		return OutOff, nil
	}
	return OutServices, fmt.Errorf("nat.outgoing을 읽을 수 없다. services와 off 가운데 하나여야 한다: %s", s)
}

// Incoming은 터널로 온 연결을 앱에 어느 주소로 보일지 정한다.
type Incoming int

const (
	// InRealIP는 목적지를 이 머신의 실제 IP로, 출발지를 상대의 실제 IP로 바꾼다. 기본값이다.
	InRealIP Incoming = iota
	// InTunnelIP는 바꾸지 않는다. 앱이 터널 IP를 본다.
	InTunnelIP
)

func (i Incoming) String() string {
	if i == InTunnelIP {
		return "터널 IP"
	}
	return "실제 IP"
}

// ParseIncoming은 csa.toml의 nat.incoming을 읽는다. 빈 값은 기본값이다.
func ParseIncoming(s string) (Incoming, error) {
	switch s {
	case "", "real-ip":
		return InRealIP, nil
	case "tunnel-ip":
		return InTunnelIP, nil
	}
	return InRealIP, fmt.Errorf("nat.incoming을 읽을 수 없다. real-ip와 tunnel-ip 가운데 하나여야 한다: %s", s)
}

// Peer는 상대 하나에 대해 규칙을 만드는 데 필요한 값이다.
type Peer struct {
	TunnelIP netip.Addr
	// RealIPs는 앱이 그 머신을 부를 때 쓰는 실제 IP다. 비어 있으면 그 상대로
	// 가는 연결은 돌리지 않고, 그 상대에서 온 연결의 출발지도 바꾸지 않는다.
	RealIPs []netip.Addr
	// Ports는 그 머신의 서비스 포트다.
	Ports []int
}

// Config는 규칙을 만드는 데 필요한 값이다.
type Config struct {
	Outgoing Outgoing
	Incoming Incoming
	// Iface는 csa가 만든 TUN 인터페이스다.
	Iface string
	// TunnelCIDR는 터널 대역이다. 출발지가 이 대역 밖인 패킷만 이 머신의 터널
	// IP로 바꾼다. 앱이 처음부터 터널 IP로 부른 패킷은 바꿀 것이 없다.
	TunnelCIDR netip.Prefix
	// SelfTunnelIP는 이 머신의 터널 IP다.
	SelfTunnelIP netip.Addr
	// SelfRealIP는 터널로 온 패킷의 목적지를 바꿀 이 머신의 실제 IP다. 실제 IP가
	// 여럿이면 첫 주소다. 보낸 쪽 앱이 어느 실제 IP로 불렀는지는 안쪽 패킷에
	// 남지 않는다.
	SelfRealIP netip.Addr
	// Peers는 이 머신 자신을 뺀 상대들이다.
	Peers []Peer
}

// Empty는 이 설정이 표를 하나도 만들지 않는지 알려 준다.
func (c Config) Empty() bool {
	return c.Outgoing == OutOff && c.Incoming == InTunnelIP
}

// Ruleset은 nft에 줄 규칙 글을 만든다.
//
// 앞의 두 줄은 앞서 돌던 csa가 남긴 표를 지우려고 둔다. 표가 없으면 만들고
// 지우므로 어느 경우에도 같은 자리에서 시작한다.
//
// 서비스 포트는 TCP와 UDP를 모두 적는다. peers.toml에는 프로토콜을 적지 않기
// 때문이다.
func Ruleset(c Config) string {
	var b strings.Builder
	b.WriteString(dropTable())
	fmt.Fprintf(&b, "table ip %s {\n", tableName)
	fmt.Fprintf(&b, "\tcounter %s {\n\t}\n", steeredCounter)
	fmt.Fprintf(&b, "\tcounter %s {\n\t}\n", presentedCounter)

	if c.Outgoing == OutServices {
		// 보내는 쪽. 목적지는 output 훅에서, 출발지는 postrouting 훅에서 바꾼다.
		// 목적지가 바뀌면 커널이 경로를 다시 찾아 TUN 인터페이스를 고른다.
		// 출발지는 그때 다시 정해지지 않으므로 따로 바꾼다. 그대로 두면 받는
		// 쪽 wg가 허용 IP 검사에서 버린다.
		b.WriteString("\n\tchain output {\n")
		b.WriteString("\t\ttype nat hook output priority dstnat; policy accept;\n")
		for _, p := range c.Peers {
			for _, real := range p.RealIPs {
				for _, port := range dedup(p.Ports) {
					fmt.Fprintf(&b, "\t\tip daddr %s tcp dport %d counter name %q dnat to %s\n",
						real, port, steeredCounter, p.TunnelIP)
					fmt.Fprintf(&b, "\t\tip daddr %s udp dport %d counter name %q dnat to %s\n",
						real, port, steeredCounter, p.TunnelIP)
				}
			}
		}
		b.WriteString("\t}\n")
		b.WriteString("\tchain postrouting {\n")
		b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
		fmt.Fprintf(&b, "\t\toifname %q ip saddr != %s snat to %s\n", c.Iface, c.TunnelCIDR, c.SelfTunnelIP)
		b.WriteString("\t}\n")
	}

	if c.Incoming == InRealIP {
		// 받는 쪽. 목적지는 prerouting 훅에서 라우팅 전에, 출발지는 input 훅에서
		// 라우팅 뒤에 바꾼다. 역경로 검사는 라우팅 시점에 도는데 그때 출발지는
		// 아직 터널 IP이므로 걸리지 않는다.
		b.WriteString("\n\tchain prerouting {\n")
		b.WriteString("\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
		if c.SelfRealIP.IsValid() {
			fmt.Fprintf(&b, "\t\tiifname %q ip daddr %s counter name %q dnat to %s\n",
				c.Iface, c.SelfTunnelIP, presentedCounter, c.SelfRealIP)
		}
		b.WriteString("\t}\n")
		b.WriteString("\tchain input {\n")
		b.WriteString("\t\ttype nat hook input priority srcnat; policy accept;\n")
		for _, p := range c.Peers {
			if len(p.RealIPs) == 0 {
				continue
			}
			fmt.Fprintf(&b, "\t\tiifname %q ip saddr %s snat to %s\n", c.Iface, p.TunnelIP, p.RealIPs[0])
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// dropTable은 이 리포의 표를 만들고 지우는 배치다. 표가 없으면 만들어서
// 지우므로 nft가 「그런 표가 없다」고 답하지 않는다.
func dropTable() string {
	return fmt.Sprintf("table ip %s\ndelete table ip %s\n", tableName, tableName)
}

func dedup(in []int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// NAT은 csa가 걸어 둔 표다.
type NAT struct {
	outgoing Outgoing
	incoming Incoming
	on       bool
	nft      string // nft 명령의 자리
	keep     bool   // 멈출 때 표를 남길지
	// unchecked는 앞서 남은 표가 있는지 보지 못했다는 뜻이다. 표를 만들지 않는
	// 설정인데 nft를 찾지 못한 자리에서 선다.
	unchecked bool
	logf      func(string, ...any)
}

func New(logf func(string, ...any)) *NAT {
	return &NAT{logf: logf}
}

// Check는 표를 걸지 않고 nft가 받아들이는지만 본다. 설정을 다시 읽을 때
// 아무것도 바꾸기 전에 부른다.
func (n *NAT) Check(c Config) error {
	if c.Empty() {
		return nil
	}
	path, err := nft.Look()
	if err != nil {
		return err
	}
	cmd := exec.Command(path, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(Ruleset(c))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft가 이 규칙을 받아들이지 않는다: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply는 표를 건다. 이미 걸려 있으면 새 표로 갈아 끼운다. csa reload가
// 상대의 실제 IP나 서비스를 바꾸면 여기를 다시 부른다. NAT의 상태는 규칙이
// 아니라 연결 추적에 있으므로 표를 다시 만들어도 맺어진 연결은 끊기지 않는다.
func (n *NAT) Apply(c Config) error {
	n.outgoing, n.incoming = c.Outgoing, c.Incoming
	if c.Empty() {
		// 앞서 돌던 csa가 남긴 표가 커널에 있을 수 있다. 이 객체가 무엇을
		// 걸었는지와 무관하게 지운다. 표가 없다는 답은 잘못이 아니다.
		checked, err := removeTable(n.logf)
		if err != nil {
			return err
		}
		n.on = false
		n.unchecked = !checked
		if !checked {
			n.logf("주소를 바꾸지 않습니다. nat.outgoing이 off이고 nat.incoming이 tunnel-ip입니다." +
				" 다만 nft를 찾지 못해 앞서 남은 표가 있는지 보지 못했습니다.")
			return nil
		}
		n.logf("주소를 바꾸지 않습니다. nat.outgoing이 off이고 nat.incoming이 tunnel-ip입니다." +
			" 앱이 실제 IP로 부른 연결은 직통으로 나가고, 터널로 온 연결은 터널 IP로 보입니다.")
		return nil
	}
	path, err := nft.Look()
	if err != nil {
		return err
	}
	n.nft = path
	n.unchecked = false
	cmd := exec.Command(path, "-f", "-")
	cmd.Stdin = strings.NewReader(Ruleset(c))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("주소를 바꾸는 표를 걸지 못했다: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	n.on = true
	n.tell(c)
	return nil
}

// tell은 무엇을 걸었는지 알리고, 이 머신의 실제 IP로 적은 주소가 실제로 이
// 머신에 붙어 있는지 본다. 붙어 있지 않으면 터널로 온 연결을 그 주소로 바꿔도
// 앱이 받지 못한다.
func (n *NAT) tell(c Config) {
	switch c.Outgoing {
	case OutServices:
		steered := 0
		for _, p := range c.Peers {
			if len(p.RealIPs) > 0 {
				steered += len(dedup(p.Ports))
			}
		}
		n.logf("앱이 상대의 실제 IP로 부른 연결을 터널로 돌립니다. 상대 %d개, 서비스 포트 %d개입니다.",
			len(c.Peers), steered)
	default:
		n.logf("앱이 상대의 실제 IP로 부른 연결을 돌리지 않습니다. nat.outgoing이 off입니다.")
	}
	switch c.Incoming {
	case InRealIP:
		if !c.SelfRealIP.IsValid() {
			n.logf("터널로 온 연결을 앱에 실제 IP로 보이려 하는데 이 머신의 실제 IP를 모릅니다." +
				" peers.toml의 자기 항목에 addresses를 적으십시오.")
			return
		}
		n.logf("터널로 온 연결을 앱에 실제 IP로 보입니다. 이 머신의 실제 IP는 %s입니다.", c.SelfRealIP)
		if !hasAddr(c.SelfRealIP) {
			n.logf("다만 그 주소가 이 머신의 인터페이스에 붙어 있지 않습니다. 터널로 온 연결을"+
				" 그 주소로 바꾸면 앱이 받지 못합니다. peers.toml의 자기 항목을 보십시오: %s", c.SelfRealIP)
		}
	default:
		n.logf("터널로 온 연결을 앱에 터널 IP 그대로 보입니다. nat.incoming이 tunnel-ip입니다.")
	}
}

// interfaceAddrs는 이 머신의 인터페이스에 붙은 주소를 모은다. 시험이 갈아
// 끼울 수 있게 변수로 둔다.
var interfaceAddrs = net.InterfaceAddrs

// hasAddr은 그 주소가 이 머신의 어느 인터페이스에 붙어 있는지 본다.
func hasAddr(a netip.Addr) bool {
	addrs, err := interfaceAddrs()
	if err != nil {
		return true // 볼 수 없으면 알리지 않는다
	}
	for _, x := range addrs {
		n, ok := x.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == a {
			return true
		}
	}
	return false
}

// removeTable은 커널에 있는 이 리포의 표를 지운다. 몇 번을 불러도 같다.
// 돌려주는 첫 값은 지웠는지 확인했는지다. nft를 찾지 못하면 거짓이다.
func removeTable(logf func(string, ...any)) (bool, error) {
	path, err := nft.Look()
	if err != nil {
		return false, nil
	}
	had := exec.Command(path, "list", "table", "ip", tableName).Run() == nil
	cmd := exec.Command(path, "-f", "-")
	cmd.Stdin = strings.NewReader(dropTable())
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, fmt.Errorf("남아 있는 주소 바꾸기 표를 지우지 못했다: %v (%s)",
			err, strings.TrimSpace(string(out)))
	}
	if had {
		logf("앞서 돌던 csa가 남긴 주소 바꾸기 표를 지웠습니다.")
	}
	return true, nil
}

// Keep은 멈출 때 표를 지우지 말라고 이른다. csa가 반쯤 걸린 상태로 멈출 때
// 쓴다. 표를 남겨 두면 앱이 실제 IP로 부른 연결이 직통으로 나가지 않고 터널로
// 들어가 서지 않는다. 인증 없이 통하는 대신 닫힌 채 실패한다.
func (n *NAT) Keep() { n.keep = true }

// Close는 걸어 둔 표를 지운다.
func (n *NAT) Close() {
	if n == nil || !n.on {
		return
	}
	if n.keep {
		n.logf("주소 바꾸기 표를 남겨 둡니다.")
		return
	}
	out, err := exec.Command(n.nft, "delete", "table", "ip", tableName).CombinedOutput()
	if err != nil {
		n.logf("주소 바꾸기 표를 지우지 못했습니다: %v (%s)", err, strings.TrimSpace(string(out)))
		return
	}
	n.on = false
	n.logf("주소 바꾸기 표를 지웠습니다.")
}

// Outgoing은 지금 걸려 있는 보내는 쪽 모드다.
func (n *NAT) Outgoing() Outgoing { return n.outgoing }

// Incoming은 지금 걸려 있는 받는 쪽 모드다.
func (n *NAT) Incoming() Incoming { return n.incoming }

// Unchecked는 앞서 남은 표가 있는지 보지 못했으면 참이다.
func (n *NAT) Unchecked() bool {
	if n == nil {
		return false
	}
	return n.unchecked
}

// Steered는 지금까지 터널로 돌린 연결 수다. NAT 규칙은 연결의 첫 패킷에만
// 걸리고 그 뒤 패킷은 연결 추적이 다루므로, 계수기가 세는 것은 연결이다.
func (n *NAT) Steered() uint64 { return n.count(steeredCounter) }

// Presented는 지금까지 앱에 실제 IP로 보인 연결 수다.
func (n *NAT) Presented() uint64 { return n.count(presentedCounter) }

func (n *NAT) count(name string) uint64 {
	if n == nil || !n.on {
		return 0
	}
	out, err := exec.Command(n.nft, "-j", "list", "counter", "ip", tableName, name).Output()
	if err != nil {
		return 0
	}
	return nft.Count(out)
}
