package nat

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/randyinthedev-hash/callsignet/internal/nft"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// base는 자기와 상대 둘이 있는 설정이다. srv-b는 실제 IP 둘과 서비스 둘, srv-c는
// 실제 IP가 없다.
func base() Config {
	return Config{
		Iface:        "cs0",
		TunnelCIDR:   netip.MustParsePrefix("10.91.0.0/24"),
		SelfTunnelIP: ip("10.91.0.1"),
		SelfRealIP:   ip("10.90.0.1"),
		Peers: []Peer{
			{TunnelIP: ip("10.91.0.2"), RealIPs: []netip.Addr{ip("10.90.0.2"), ip("10.90.9.2")}, Ports: []int{8080, 9090, 8080}},
			{TunnelIP: ip("10.91.0.3"), Ports: []int{8080}},
		},
	}
}

// 앞서 돌던 csa가 남긴 표를 지우고 시작해야 한다. 표가 없어도 실패하지 않도록
// 만들고 지운다.
func TestRulesetStartsClean(t *testing.T) {
	lines := strings.Split(Ruleset(base()), "\n")
	if lines[0] != "table ip callsignet-nat" || lines[1] != "delete table ip callsignet-nat" {
		t.Errorf("앞의 두 줄이 표를 지워야 하는데:\n%s", strings.Join(lines[:3], "\n"))
	}
}

// 보내는 쪽 규칙이다. 상대의 실제 IP마다, 서비스 포트마다, TCP와 UDP를 적는다.
// 실제 IP가 없는 상대는 적지 않는다. 출발지는 터널 대역 밖일 때만 바꾼다.
func TestRulesetOutgoing(t *testing.T) {
	got := Ruleset(base())
	for _, want := range []string{
		"type nat hook output priority dstnat",
		`ip daddr 10.90.0.2 tcp dport 8080 counter name "steered" dnat to 10.91.0.2`,
		`ip daddr 10.90.0.2 udp dport 8080 counter name "steered" dnat to 10.91.0.2`,
		`ip daddr 10.90.0.2 tcp dport 9090 counter name "steered" dnat to 10.91.0.2`,
		`ip daddr 10.90.9.2 tcp dport 8080 counter name "steered" dnat to 10.91.0.2`,
		"type nat hook postrouting priority srcnat",
		`oifname "cs0" ip saddr != 10.91.0.0/24 snat to 10.91.0.1`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("없다: %s\n%s", want, got)
		}
	}
	if strings.Contains(got, "dnat to 10.91.0.3") {
		t.Errorf("실제 IP가 없는 상대로 돌리는 줄이 있다:\n%s", got)
	}
	if strings.Count(got, "ip daddr 10.90.0.2 tcp dport 8080") != 1 {
		t.Errorf("겹친 포트를 두 번 적었다:\n%s", got)
	}
}

// 받는 쪽 규칙이다. 목적지는 prerouting에서 자기 실제 IP로, 출발지는 input에서
// 상대의 첫 실제 IP로 바꾼다. 실제 IP가 없는 상대의 출발지는 바꾸지 않는다.
func TestRulesetIncoming(t *testing.T) {
	got := Ruleset(base())
	for _, want := range []string{
		"type nat hook prerouting priority dstnat",
		`iifname "cs0" ip daddr 10.91.0.1 counter name "presented" dnat to 10.90.0.1`,
		"type nat hook input priority srcnat",
		`iifname "cs0" ip saddr 10.91.0.2 snat to 10.90.0.2`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("없다: %s\n%s", want, got)
		}
	}
	if strings.Contains(got, "ip saddr 10.91.0.3") {
		t.Errorf("실제 IP가 없는 상대의 출발지를 바꾸는 줄이 있다:\n%s", got)
	}
	if strings.Contains(got, "snat to 10.90.9.2") {
		t.Errorf("둘째 실제 IP로 바꾸는 줄이 있다. 첫 주소만 써야 한다:\n%s", got)
	}
}

// 모드마다 체인이 갈린다. 둘 다 끄면 표를 만들지 않는다.
func TestRulesetModes(t *testing.T) {
	c := base()
	c.Outgoing = OutOff
	got := Ruleset(c)
	if strings.Contains(got, "chain output") || strings.Contains(got, "chain postrouting") {
		t.Errorf("outgoing이 off인데 보내는 쪽 체인이 있다:\n%s", got)
	}
	if !strings.Contains(got, "chain prerouting") {
		t.Errorf("outgoing이 off여도 받는 쪽 체인은 있어야 한다:\n%s", got)
	}

	c = base()
	c.Incoming = InTunnelIP
	got = Ruleset(c)
	if strings.Contains(got, "chain prerouting") || strings.Contains(got, "chain input") {
		t.Errorf("incoming이 tunnel-ip인데 받는 쪽 체인이 있다:\n%s", got)
	}
	if !strings.Contains(got, "chain output") {
		t.Errorf("incoming이 tunnel-ip여도 보내는 쪽 체인은 있어야 한다:\n%s", got)
	}

	c.Outgoing = OutOff
	if !c.Empty() {
		t.Error("둘 다 껐는데 표를 만들려 한다")
	}
	if base().Empty() {
		t.Error("기본 설정인데 표를 만들지 않으려 한다")
	}
}

// 자기 실제 IP를 모르면 목적지를 바꾸는 줄을 만들지 않는다. 설정 검사가 그 자리를
// 먼저 잡지만, 여기서도 잘못된 줄을 만들지 않아야 nft가 거절하지 않는다.
func TestRulesetWithoutSelfRealIP(t *testing.T) {
	c := base()
	c.SelfRealIP = netip.Addr{}
	got := Ruleset(c)
	if strings.Contains(got, "dnat to 10.90.0.1") || strings.Contains(got, `ip daddr 10.91.0.1 counter`) {
		t.Errorf("자기 실제 IP를 모르는데 목적지를 바꾸는 줄이 있다:\n%s", got)
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]Outgoing{"": OutServices, "services": OutServices, "off": OutOff} {
		got, err := ParseOutgoing(in)
		if err != nil || got != want {
			t.Errorf("outgoing %q: %v, %v", in, got, err)
		}
	}
	if _, err := ParseOutgoing("돌려"); err == nil {
		t.Error("outgoing의 모르는 값을 받아들였다")
	}
	for in, want := range map[string]Incoming{"": InRealIP, "real-ip": InRealIP, "tunnel-ip": InTunnelIP} {
		got, err := ParseIncoming(in)
		if err != nil || got != want {
			t.Errorf("incoming %q: %v, %v", in, got, err)
		}
	}
	if _, err := ParseIncoming("보여"); err == nil {
		t.Error("incoming의 모르는 값을 받아들였다")
	}
}

// fakeNft는 PATH에 가짜 nft를 놓고 그것이 받은 인자와 표준 입력을 적어 둔다.
// 진짜 nft는 root가 있어야 돌므로 단위 시험에서 쓸 수 없다. guard의 것과 같다.
func fakeNft(t *testing.T, listExit, exitCode int, stderr string) (calls func() string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "부른것")
	q := strconv.Quote(log)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + q + "\n"
	script += "while IFS= read -r line; do printf '%s\\n' \"$line\" >> " + q + "; done\n"
	script += "if [ \"$1\" = list ]; then exit " + strconv.Itoa(listExit) + "; fi\n"
	if stderr != "" {
		script += "printf '%s\\n' " + strconv.Quote(stderr) + " >&2\n"
	}
	script += "exit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return func() string {
		b, err := os.ReadFile(log)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func noNft(t *testing.T) {
	t.Helper()
	old := nft.Look
	nft.Look = func() (string, error) { return "", errors.New("nft를 찾지 못했다") }
	t.Cleanup(func() { nft.Look = old })
}

func said(lines *[]string) func(string, ...any) {
	return func(f string, a ...any) { *lines = append(*lines, fmt.Sprintf(f, a...)) }
}

func off() Config {
	c := base()
	c.Outgoing, c.Incoming = OutOff, InTunnelIP
	return c
}

// 둘 다 끄면 표를 만들지 않되, 앞서 돌던 csa가 남긴 표는 지운다. 직통 경로 표와
// 같은 까닭이다. 남은 표가 있으면 csa는 「바꾸지 않는다」고 말하면서 실제로는 옛
// 표가 주소를 바꾼다.
func TestOff앞서남은표를지운다(t *testing.T) {
	calls := fakeNft(t, 0, 0, "")
	var lines []string
	n := New(said(&lines))
	if err := n.Apply(off()); err != nil {
		t.Fatalf("off를 걸지 못했다: %v", err)
	}
	if got := calls(); !strings.Contains(got, "delete table ip callsignet-nat") {
		t.Fatalf("남은 표를 지우지 않았다. nft를 부른 것: %q", got)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "남긴 주소 바꾸기 표를 지웠습니다") {
		t.Fatalf("지웠다고 알리지 않았다. 찍은 것: %v", lines)
	}
	if n.Steered() != 0 || n.Presented() != 0 {
		t.Fatal("표가 없는데 계수기를 읽었다")
	}
}

func TestOff표가없어도잘못이아니다(t *testing.T) {
	fakeNft(t, 1, 0, "")
	var lines []string
	n := New(said(&lines))
	if err := n.Apply(off()); err != nil {
		t.Fatalf("표가 없는 것을 잘못으로 보았다: %v", err)
	}
	if strings.Contains(strings.Join(lines, "\n"), "지웠습니다") {
		t.Fatalf("지운 것이 없는데 지웠다고 알렸다. 찍은 것: %v", lines)
	}
	if n.Unchecked() {
		t.Fatal("확인했는데 보지 못했다고 알린다")
	}
}

func TestOffnft가없으면확인하지못했다고알린다(t *testing.T) {
	noNft(t)
	var lines []string
	n := New(said(&lines))
	if err := n.Apply(off()); err != nil {
		t.Fatalf("nft가 없다고 기동을 막았다: %v", err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "보지 못했습니다") {
		t.Fatalf("확인하지 못했다고 알리지 않았다. 찍은 것: %v", lines)
	}
	if !n.Unchecked() {
		t.Fatal("보지 못했는데 status에는 그 사실을 싣지 않는다")
	}
}

// 표를 만드는 설정인데 nft가 없으면 뜨지 않는다. 바꾸라고 해 놓고 바꾸지 않은
// 채로 도는 것보다 낫다.
func TestApply는nft가없으면막는다(t *testing.T) {
	noNft(t)
	n := New(func(string, ...any) {})
	if err := n.Apply(base()); err == nil {
		t.Fatal("nft가 없는데 표를 걸었다고 했다")
	}
	if err := n.Check(base()); err == nil {
		t.Fatal("nft가 없는데 받아들였다고 했다")
	}
	if err := n.Check(off()); err != nil {
		t.Fatalf("표를 만들지 않는 설정은 nft가 없어도 받아들여야 한다: %v", err)
	}
}

// onlyAddr은 이 머신에 그 주소 하나만 붙어 있는 것처럼 꾸민다.
func onlyAddr(t *testing.T, cidr string) {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	// net.InterfaceAddrs가 내놓는 IPNet의 IP는 대역 주소가 아니라 인터페이스에 붙은
	// 주소다. ParseCIDR는 대역 주소로 깎으므로 되돌린다.
	n.IP = ip
	old := interfaceAddrs
	interfaceAddrs = func() ([]net.Addr, error) { return []net.Addr{n}, nil }
	t.Cleanup(func() { interfaceAddrs = old })
}

// 표를 걸면 무엇을 걸었는지 알리고, 규칙 글을 표준 입력으로 준다.
func TestApply는규칙을건다(t *testing.T) {
	calls := fakeNft(t, 1, 0, "")
	onlyAddr(t, "10.90.0.7/24")
	var lines []string
	n := New(said(&lines))
	if err := n.Apply(base()); err != nil {
		t.Fatalf("걸지 못했다: %v", err)
	}
	got := calls()
	if !strings.Contains(got, "-f -") || !strings.Contains(got, "dnat to 10.91.0.2") {
		t.Fatalf("규칙 글을 nft에 주지 않았다: %q", got)
	}
	spoke := strings.Join(lines, "\n")
	if !strings.Contains(spoke, "터널로 돌립니다. 상대 2개, 서비스 포트 2개") {
		t.Fatalf("무엇을 걸었는지 알리지 않았다: %v", lines)
	}
	if !strings.Contains(spoke, "실제 IP는 10.90.0.1") {
		t.Fatalf("이 머신의 실제 IP를 알리지 않았다: %v", lines)
	}
	// 이 머신에 10.90.0.1이 붙어 있지 않으므로 그 사실도 알려야 한다.
	if !strings.Contains(spoke, "붙어 있지 않습니다") {
		t.Fatalf("붙어 있지 않은 주소를 알리지 않았다: %v", lines)
	}
	n.Close()
	if !strings.Contains(calls(), "delete table ip callsignet-nat") {
		t.Fatal("멈추면서 표를 지우지 않았다")
	}

	// 붙어 있으면 알리지 않는다.
	onlyAddr(t, "10.90.0.1/24")
	lines = nil
	if err := New(said(&lines)).Apply(base()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(lines, "\n"), "붙어 있지 않습니다") {
		t.Fatalf("붙어 있는데 붙어 있지 않다고 알렸다: %v", lines)
	}
}

// 반쯤 걸린 상태로 멈출 때는 표를 남긴다.
func TestKeep은표를남긴다(t *testing.T) {
	calls := fakeNft(t, 1, 0, "")
	n := New(func(string, ...any) {})
	if err := n.Apply(base()); err != nil {
		t.Fatal(err)
	}
	before := calls()
	n.Keep()
	n.Close()
	if calls() != before {
		t.Fatal("남기라고 했는데 nft를 불렀다")
	}
}
