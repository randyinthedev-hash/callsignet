package guard

import (
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
			"ct state established,related accept",
			"udp dport 51820 accept",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%v에 없다: %s\n%s", m, want, got)
			}
		}
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
