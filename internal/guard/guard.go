// Package guard는 csa가 지키는 서비스의 직통 경로를 닫는다.
//
// csa는 터널을 지나는 패킷만 본다. 다른 머신이 이 머신의 실제 IP로 붙으면 그
// 패킷은 TUN 인터페이스를 지나지 않으므로 csa가 보지 못하고, 커널이 듣고 있는
// 앱에게 바로 넘긴다. 그대로 두면 정책이 터널로 들어온 연결에만 걸린다.
//
// 그래서 csa는 자기 이름의 nftables 표를 하나 만들어 그 경로를 닫는다. 조직이
// 이미 걸어 둔 규칙은 읽지도 고치지도 않는다. nftables는 표마다 독립이고 어느
// 표에서든 버리면 버려지므로 자기 표만 다루면 된다.
package guard

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

const (
	tableName   = "callsignet"
	counterName = "blocked"
)

// Mode는 무엇까지 닫을지 정한다.
type Mode int

const (
	// ModeServices는 peers.toml에 적힌 이 머신의 서비스 포트만 닫는다. 기본값이다.
	ModeServices Mode = iota
	// ModeAll은 운영자가 적은 예외 포트 말고 모두 닫는다.
	ModeAll
	// ModeOff는 닫지 않는다.
	ModeOff
)

func (m Mode) String() string {
	switch m {
	case ModeAll:
		return "예외 말고 모두 닫음"
	case ModeOff:
		return "닫지 않음"
	default:
		return "서비스 포트만 닫음"
	}
}

// ParseMode는 csa.toml에 적은 값을 읽는다. 빈 값은 기본값이다.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "", "services":
		return ModeServices, nil
	case "all":
		return ModeAll, nil
	case "off":
		return ModeOff, nil
	}
	return ModeServices, fmt.Errorf("guard.mode를 읽을 수 없다. services, all, off 가운데 하나여야 한다: %s", s)
}

// Config는 규칙을 만드는 데 필요한 값이다.
type Config struct {
	Mode Mode
	// Iface는 csa가 만든 TUN 인터페이스다. 여기로 들어온 것은 이미 wg가 확정한
	// 패킷이므로 그대로 통과시킨다.
	Iface string
	// WGPort는 wg가 듣는 포트다. 이 문이 닫히면 터널 자체가 서지 않는다.
	WGPort int
	// Ports는 이 머신의 서비스 포트다. ModeServices에서 이것만 닫는다.
	Ports []int
	// KeepTCP와 KeepUDP는 ModeAll에서 열어 둘 포트다.
	KeepTCP []int
	KeepUDP []int
}

// Ruleset은 nft에게 줄 규칙 글을 만든다.
//
// 앞의 두 줄은 앞서 돌던 csa가 남긴 표를 지우려고 둔다. 표가 없으면 만들고
// 지우므로 어느 경우에도 같은 자리에서 시작한다.
//
// 서비스 포트는 TCP와 UDP를 모두 닫는다. peers.toml에는 프로토콜을 적지 않기
// 때문이다.
func Ruleset(c Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", tableName)
	fmt.Fprintf(&b, "delete table inet %s\n", tableName)
	fmt.Fprintf(&b, "table inet %s {\n", tableName)
	fmt.Fprintf(&b, "\tcounter %s {\n\t}\n\n", counterName)
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	fmt.Fprintf(&b, "\t\tiifname %q accept\n", c.Iface)
	b.WriteString("\t\tct state established,related accept\n")
	fmt.Fprintf(&b, "\t\tudp dport %d accept\n", c.WGPort)

	if c.Mode == ModeAll {
		// ICMP를 버리면 경로 MTU 발견이 되지 않아 wg 자신의 패킷이 조용히
		// 사라진다. 그래서 열어 둔다.
		b.WriteString("\t\tmeta l4proto { icmp, ipv6-icmp } accept\n")
		for _, p := range dedup(c.KeepTCP) {
			fmt.Fprintf(&b, "\t\ttcp dport %d accept\n", p)
		}
		for _, p := range dedup(c.KeepUDP) {
			fmt.Fprintf(&b, "\t\tudp dport %d accept\n", p)
		}
		fmt.Fprintf(&b, "\t\tcounter name %q drop\n", counterName)
	} else {
		for _, p := range dedup(c.Ports) {
			fmt.Fprintf(&b, "\t\ttcp dport %d counter name %q drop\n", p, counterName)
			fmt.Fprintf(&b, "\t\tudp dport %d counter name %q drop\n", p, counterName)
		}
	}
	b.WriteString("\t}\n}\n")
	return b.String()
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

// Guard는 csa가 걸어 둔 규칙이다.
type Guard struct {
	mode Mode
	on   bool
	logf func(string, ...any)
}

func New(logf func(string, ...any)) *Guard {
	return &Guard{logf: logf}
}

// Apply는 규칙을 건다. 이미 걸려 있으면 새 규칙으로 갈아 끼운다. csa reload가
// 서비스 목록을 바꾸면 여기도 다시 부른다.
func (g *Guard) Apply(c Config) error {
	g.mode = c.Mode
	if c.Mode == ModeOff {
		if g.on {
			g.Close()
		}
		g.logf("직통 경로를 닫지 않습니다. guard.mode가 off입니다." +
			" 이 머신의 서비스 포트는 터널 밖에서도 열려 있습니다.")
		return nil
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft를 찾지 못했다. nftables를 설치하거나" +
			" csa.toml에 guard.mode = \"off\"를 두라")
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(Ruleset(c))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("직통 경로를 닫지 못했다: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	g.on = true
	switch c.Mode {
	case ModeAll:
		g.logf("직통 경로를 닫았습니다. 예외로 둔 포트 말고 모두 닫습니다."+
			" 열어 둔 TCP 포트 %v, UDP 포트 %v", dedup(c.KeepTCP), dedup(c.KeepUDP))
	default:
		g.logf("직통 경로를 닫았습니다. 이 머신의 서비스 포트만 닫습니다: %v", dedup(c.Ports))
	}
	return nil
}

// Close는 걸어 둔 표를 지운다. 조직의 다른 규칙은 건드리지 않는다.
func (g *Guard) Close() {
	if g == nil || !g.on {
		return
	}
	out, err := exec.Command("nft", "delete", "table", "inet", tableName).CombinedOutput()
	if err != nil {
		g.logf("직통 경로 규칙을 지우지 못했습니다: %v (%s)", err, strings.TrimSpace(string(out)))
		return
	}
	g.on = false
	g.logf("직통 경로 규칙을 지웠습니다.")
}

// Mode는 지금 걸려 있는 모드다.
func (g *Guard) Mode() Mode { return g.mode }

// Blocked는 지금까지 막은 패킷 수다. nftables 계수기가 센 값이다.
func (g *Guard) Blocked() uint64 {
	if g == nil || !g.on {
		return 0
	}
	out, err := exec.Command("nft", "-j", "list", "counter", "inet", tableName, counterName).Output()
	if err != nil {
		return 0
	}
	return countOf(out)
}

// countOf는 nft가 내놓은 JSON에서 계수기 값을 뽑는다.
func countOf(b []byte) uint64 {
	var doc struct {
		Nftables []struct {
			Counter struct {
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return 0
	}
	for _, item := range doc.Nftables {
		if item.Counter.Packets > 0 {
			return item.Counter.Packets
		}
	}
	return 0
}
