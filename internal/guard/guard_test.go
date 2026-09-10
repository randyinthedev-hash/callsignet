package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func base() Config {
	return Config{Iface: "cs0", WGPort: 51820, Ports: []int{8080, 7070}}
}

// 어느 모드든 반드시 있어야 하는 것들이다. 이것이 빠지면 터널 자체가 서지 않거나
// 이 머신이 자기와 말하지 못한다.
func TestRulesetAlwaysKeepsTheseOpen(t *testing.T) {
	for _, m := range []Mode{ModeServices, ModeAll} {
		c := base()
		c.Mode = m
		got := Ruleset(c)
		for _, want := range []string{
			`iifname "lo" accept`,
			`iifname "cs0" accept`,
			"udp dport 51820 accept",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%v에 없다: %s\n%s", m, want, got)
			}
		}
	}
}

// 이미 맺은 연결을 들이는 줄은 모두 버리는 모드에만 둔다.
//
// 서비스 포트만 닫는 모드에서는 그 줄이 필요 없다. 그 모드는 서비스 포트 말고
// 아무것도 버리지 않기 때문이다. 그리고 그 줄을 두면 csa가 뜨기 전에 직통으로
// 맺어진 연결이 conntrack에 남아 그대로 이어진다.
func TestEstablishedOnlyInAllMode(t *testing.T) {
	c := base()
	if strings.Contains(Ruleset(c), "ct state") {
		t.Errorf("서비스 포트만 닫는 모드에 이미 맺은 연결을 들이는 줄이 있다:\n%s", Ruleset(c))
	}
	c.Mode = ModeAll
	if !strings.Contains(Ruleset(c), "ct state established,related accept") {
		t.Errorf("모두 버리는 모드에는 그 줄이 있어야 한다:\n%s", Ruleset(c))
	}
}

// 앞서 돌던 csa가 남긴 표를 지우고 시작해야 한다. 표가 없어도 실패하지 않도록
// 만들고 지운다.
func TestRulesetStartsClean(t *testing.T) {
	lines := strings.Split(Ruleset(base()), "\n")
	if lines[0] != "table inet callsignet" || lines[1] != "delete table inet callsignet" {
		t.Errorf("앞의 두 줄이 표를 지워야 하는데:\n%s", strings.Join(lines[:3], "\n"))
	}
}

func TestServicesModeClosesOnlyServicePorts(t *testing.T) {
	got := Ruleset(base())
	for _, want := range []string{
		`tcp dport 7070 counter name "blocked" drop`,
		`udp dport 7070 counter name "blocked" drop`,
		`tcp dport 8080 counter name "blocked" drop`,
		`udp dport 8080 counter name "blocked" drop`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("없다: %s\n%s", want, got)
		}
	}
	// 마지막에 모두 버리는 규칙이 있으면 SSH까지 끊긴다.
	if strings.Contains(got, "\t\tcounter name \"blocked\" drop\n") {
		t.Errorf("서비스 포트만 닫아야 하는데 모두 버린다:\n%s", got)
	}
}

func TestAllModeClosesEverythingButExceptions(t *testing.T) {
	c := base()
	c.Mode = ModeAll
	c.KeepTCP = []int{22}
	c.KeepUDP = []int{123}
	got := Ruleset(c)
	for _, want := range []string{
		"tcp dport 22 accept",
		"udp dport 123 accept",
		"meta l4proto { icmp, ipv6-icmp } accept",
		"\t\tcounter name \"blocked\" drop\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("없다: %q\n%s", want, got)
		}
	}
	// 모두 버리므로 서비스 포트를 따로 적을 까닭이 없다.
	if strings.Contains(got, "tcp dport 8080") {
		t.Errorf("모두 버리는 모드인데 서비스 포트를 따로 적었다:\n%s", got)
	}
	// 열어 두는 규칙이 버리는 규칙보다 앞에 있어야 한다.
	if strings.Index(got, "tcp dport 22 accept") > strings.Index(got, "\t\tcounter name \"blocked\" drop") {
		t.Errorf("예외가 버리는 규칙 뒤에 있다:\n%s", got)
	}
}

// 같은 포트를 두 번 적어도 규칙이 두 번 나오면 안 된다.
func TestRulesetDedupsPorts(t *testing.T) {
	c := base()
	c.Ports = []int{8080, 8080, 7070}
	got := Ruleset(c)
	if n := strings.Count(got, "tcp dport 8080"); n != 1 {
		t.Errorf("한 번이어야 하는데 %d번", n)
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{
		"":         ModeServices,
		"services": ModeServices,
		"all":      ModeAll,
		"off":      ModeOff,
	} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("%q: %v여야 하는데 %v (%v)", in, want, got, err)
		}
	}
	if _, err := ParseMode("아무거나"); err == nil {
		t.Error("모르는 값을 받아들였다")
	}
}

func TestCountOf(t *testing.T) {
	out := []byte(`{"nftables":[{"metainfo":{"version":"1.0.9"}},` +
		`{"counter":{"family":"inet","name":"blocked","table":"callsignet",` +
		`"handle":1,"packets":12,"bytes":720}}]}`)
	if got := countOf(out); got != 12 {
		t.Errorf("12여야 하는데 %d", got)
	}
	if got := countOf([]byte("JSON이 아니다")); got != 0 {
		t.Errorf("읽지 못하면 0이어야 하는데 %d", got)
	}
}

// fakeNft는 PATH에 가짜 nft를 놓고 그것이 받은 인자와 표준 입력을 적어 둔다.
// 진짜 nft는 root가 있어야 돌므로 단위 시험에서 쓸 수 없다.
//
// listExit는 「list table」을 물었을 때 내놓을 값이다. 0이면 표가 있다는 뜻이고
// 0이 아니면 없다는 뜻이다. exitCode는 나머지 부름에 내놓을 값이다.
func fakeNft(t *testing.T, listExit, exitCode int, stderr string) (calls func() string) {
	t.Helper()
	dir := t.TempDir()
	// 이름에 빈칸을 두지 않는다. 셸의 방향 바꾸기에서 갈라진다.
	log := filepath.Join(dir, "부른것")
	q := strconv.Quote(log)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + q + "\n"
	// 규칙 글은 인자가 아니라 표준 입력으로 온다. 그것도 적어 두어야 무엇을
	// 지우라고 했는지 시험이 볼 수 있다. read와 printf는 셸에 딸린 것이라
	// PATH가 이 임시 폴더 하나뿐이어도 돈다. cat은 그 자리에서 찾지 못한다.
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

// noNft는 nft를 찾지 못하는 자리를 만든다. PATH만 비워서는 모자라다. findNft가
// /usr/sbin과 /sbin도 보는데 시험을 돌리는 머신에 그것이 있을 수 있다.
func noNft(t *testing.T) {
	t.Helper()
	old := lookNft
	lookNft = func() (string, error) { return "", errors.New("nft를 찾지 못했다") }
	t.Cleanup(func() { lookNft = old })
}

// said는 로그로 찍힌 문구를 모은다.
func said(lines *[]string) func(string, ...any) {
	return func(f string, a ...any) { *lines = append(*lines, fmt.Sprintf(f, a...)) }
}

// TestOff앞서남은표를지운다는 앞서 돌던 csa가 남긴 표를 새 csa가 지우는지 본다.
//
// 반쯤 걸린 상태로 멈출 때 csa는 표를 일부러 남긴다. 운영자가 그것을 풀려고
// guard.mode를 off로 바꿔 다시 띄우는데, 새 Guard 객체는 자기가 건 것이 없다고
// 여겨 아무것도 지우지 않았다. 그러면 csa는 「닫지 않는다」고 알리면서 실제로는
// 앞선 표가 계속 포트를 막는다.
func TestOff앞서남은표를지운다(t *testing.T) {
	calls := fakeNft(t, 0, 0, "")
	var lines []string
	g := New(said(&lines))
	if err := g.Apply(Config{Mode: ModeOff}); err != nil {
		t.Fatalf("off를 걸지 못했다: %v", err)
	}
	got := calls()
	if !strings.Contains(got, "delete table inet callsignet") {
		t.Fatalf("남은 표를 지우지 않았다. nft를 부른 것: %q", got)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "남긴 직통 경로 규칙을 지웠습니다") {
		t.Fatalf("지웠다고 알리지 않았다. 찍은 것: %v", lines)
	}
}

// TestOff표가없어도잘못이아니다는 지우려던 것이 이미 없는 자리를 본다.
//
// 표를 만들고 지우는 배치를 쓰므로 nft는 표가 없어도 잘못이라고 답하지 않는다.
// 그래서 이 자리에서는 아무 말도 하지 않아야 한다. 지운 것이 없기 때문이다.
func TestOff표가없어도잘못이아니다(t *testing.T) {
	fakeNft(t, 1, 0, "")
	var lines []string
	g := New(said(&lines))
	if err := g.Apply(Config{Mode: ModeOff}); err != nil {
		t.Fatalf("표가 없는 것을 잘못으로 보았다: %v", err)
	}
	if strings.Contains(strings.Join(lines, "\n"), "지웠습니다") {
		t.Fatalf("지운 것이 없는데 지웠다고 알렸다. 찍은 것: %v", lines)
	}
}

// TestOff지우지못하면알린다는 다른 까닭으로 실패한 것을 삼키지 않는지 본다.
func TestOff지우지못하면알린다(t *testing.T) {
	fakeNft(t, 0, 1, "Error: Could not process rule: Operation not permitted")
	g := New(func(string, ...any) {})
	if err := g.Apply(Config{Mode: ModeOff}); err == nil {
		t.Fatal("지우지 못했는데 걸었다고 했다")
	}
}

// TestOffnft가없으면확인하지못했다고알린다는 nft 실행 파일이 없는 자리를 본다.
//
// 커널에 걸린 표는 nft 실행 파일을 지워도 남는다. 그러므로 nft가 없는 것을
// 「표도 없다」로 볼 수 없다. 앞서는 그렇게 보아서, csa가 「포트가 열려 있다」고
// 알리는 동안 옛 표가 계속 그 포트를 막을 수 있었다.
func TestOffnft가없으면확인하지못했다고알린다(t *testing.T) {
	noNft(t)
	var lines []string
	g := New(said(&lines))
	if err := g.Apply(Config{Mode: ModeOff}); err != nil {
		t.Fatalf("nft가 없다고 기동을 막았다: %v", err)
	}
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "보지 못했습니다") {
		t.Fatalf("확인하지 못했다고 알리지 않았다. 찍은 것: %v", lines)
	}
	if strings.Contains(got, "터널 밖에서도 열려 있습니다") {
		t.Fatalf("확인하지 못했는데 열려 있다고 단정했다. 찍은 것: %v", lines)
	}
	// 기동 로그에만 두면 그때 화면을 본 사람만 안다. csa status도 이것을 실어
	// 보내야 뒤에 상태를 묻는 사람이 안다.
	if !g.Unchecked() {
		t.Fatal("보지 못했는데 status에는 그 사실을 싣지 않는다")
	}
}

// TestOff확인했으면status에알리지않는다는 확인한 자리에서 그 값이 서지 않는지 본다.
func TestOff확인했으면status에알리지않는다(t *testing.T) {
	fakeNft(t, 1, 0, "")
	g := New(func(string, ...any) {})
	if err := g.Apply(Config{Mode: ModeOff}); err != nil {
		t.Fatalf("off를 걸지 못했다: %v", err)
	}
	if g.Unchecked() {
		t.Fatal("확인했는데 보지 못했다고 알린다")
	}
}
