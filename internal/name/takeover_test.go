package name

import (
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := []struct {
		link string
		rc   bool
		want Manager
	}{
		{"../run/systemd/resolve/stub-resolv.conf", true, ManagerResolved},
		{"/run/systemd/resolve/resolv.conf", true, ManagerResolved},
		{"/run/NetworkManager/resolv.conf", false, ManagerNetworkManager},
		{"", false, ManagerFile},
		{"", true, ManagerFile}, // resolvectl이 있어도 거치지 않으면 직접 고친다
	}
	for _, c := range cases {
		if got := Detect(c.link, c.rc); got != c.want {
			t.Errorf("%q는 %s여야 하는데 %s", c.link, c.want, got)
		}
	}
}

func TestResolvConfPutsUsFirst(t *testing.T) {
	old := "nameserver 10.0.0.53\nnameserver 8.8.8.8\noptions timeout:1\n"
	got := ResolvConf(old, "127.0.0.54", "cs.example.internal")
	lines := []string{}
	for _, l := range strings.Split(got, "\n") {
		if strings.HasPrefix(l, "nameserver ") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 3 || lines[0] != "nameserver 127.0.0.54" {
		t.Fatalf("csa가 첫 줄이어야 하는데 %v", lines)
	}
	// 원래 리졸버를 남겨야 csa가 멈춰도 다른 이름 해석이 산다.
	if lines[1] != "nameserver 10.0.0.53" || lines[2] != "nameserver 8.8.8.8" {
		t.Fatalf("원래 리졸버를 잃었다: %v", lines)
	}
	if !strings.Contains(got, "options timeout:1") {
		t.Error("options를 잃었다")
	}
	if !strings.Contains(got, "search cs.example.internal") {
		t.Error("내부 도메인을 search에 넣지 않았다")
	}
}

func TestResolvConfDoesNotRepeatItself(t *testing.T) {
	// 이미 고친 파일을 다시 읽어도 우리 주소가 두 번 들어가면 안 된다.
	once := ResolvConf("nameserver 10.0.0.53\n", "127.0.0.54", "cs.example.internal")
	twice := ResolvConf(once, "127.0.0.54", "cs.example.internal")
	if strings.Count(twice, "nameserver 127.0.0.54") != 1 {
		t.Fatalf("우리 주소가 여러 번 들어갔다:\n%s", twice)
	}
}

func TestResolvedArgs(t *testing.T) {
	args := ResolvedArgs("cs0", "127.0.0.54", "cs.example.internal", "0.91.10.in-addr.arpa")
	if len(args) != 2 {
		t.Fatalf("두 벌이어야 하는데 %d벌", len(args))
	}
	joined := strings.Join(args[1], " ")
	// 역방향 구역을 빠뜨리면 역방향 질의가 회사 DNS로 간다.
	if !strings.Contains(joined, "~0.91.10.in-addr.arpa") {
		t.Fatalf("역방향 구역이 없다: %s", joined)
	}
	if !strings.Contains(joined, "~cs.example.internal") {
		t.Fatalf("내부 도메인이 없다: %s", joined)
	}
}
