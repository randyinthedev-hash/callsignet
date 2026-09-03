package control

import (
	"strings"
	"testing"
	"time"
)

func TestSpan(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{3 * time.Second, "3초"},
		{90 * time.Second, "1분 30초"},
		{2*time.Hour + 5*time.Minute, "2시간 5분"},
		{-time.Second, "0초"},
	}
	for _, c := range cases {
		if got := span(c.d); got != c.want {
			t.Errorf("%v: %s여야 하는데 %s", c.d, c.want, got)
		}
	}
}

func TestSize(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1536, "1.5 KiB"},
		{3 * 1024 * 1024, "3.0 MiB"},
	}
	for _, c := range cases {
		if got := size(c.n); got != c.want {
			t.Errorf("%d: %s여야 하는데 %s", c.n, c.want, got)
		}
	}
}

func TestWidthCountsHangulAsTwo(t *testing.T) {
	if got := width("받음"); got != 4 {
		t.Errorf("4여야 하는데 %d", got)
	}
	if got := width("srv-a"); got != 5 {
		t.Errorf("5여야 하는데 %d", got)
	}
}

// 열이 맞는지 본다. 첫 칸의 길이가 줄마다 달라도 둘째 열은 같은 칸에서
// 시작해야 한다.
func TestTableAligns(t *testing.T) {
	out := table([][]string{
		{"peer", "받음"},
		{"srv-b", "1.5 KiB"},
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("두 줄이어야 하는데 %d줄", len(lines))
	}
	head := width(lines[0][:strings.Index(lines[0], "받음")])
	body := width(lines[1][:strings.Index(lines[1], "1.5 KiB")])
	if head != body {
		t.Errorf("둘째 열이 어긋났다. %d칸과 %d칸이다:\n%s", head, body, out)
	}
}

func TestFormat(t *testing.T) {
	now := time.Date(2026, 9, 3, 18, 0, 0, 0, time.UTC)
	s := Status{
		PeerID: "srv-a", Iface: "cs0", TunnelIP: "10.91.0.1",
		Domain: "cs.test.internal", Resolver: "직접 관리",
		Since: now.Add(-90 * time.Second),
		Peers: []PeerStatus{
			{PeerID: "srv-c", TunnelIP: "10.91.0.3"},
			{PeerID: "srv-b", TunnelIP: "10.91.0.2", Endpoint: "10.90.0.2:51820",
				Handshake: now.Add(-12 * time.Second), RxBytes: 1536, TxBytes: 512},
		},
	}
	out := Format(s, now)
	for _, want := range []string{
		"csa srv-a가 돕니다. 기동한 지 1분 30초 지났습니다.",
		"이름 해석 관리 주체는 직접 관리입니다.",
		"10.90.0.2:51820", "12초 전", "1.5 KiB", "512 B",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("없다: %q\n%s", want, out)
		}
	}
	// 세션을 맺지 않은 상대는 handshake를 없음으로 적고 출발지 자리에 -를 놓는다.
	var srvC string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "srv-c") {
			srvC = line
		}
	}
	if !strings.Contains(srvC, "없음") || !strings.Contains(srvC, "-") {
		t.Errorf("srv-c 줄이 이상하다: %q", srvC)
	}
	// 정렬은 peer-id 차례다.
	if strings.Index(out, "srv-b") > strings.Index(out, "srv-c") {
		t.Error("peer-id 차례로 늘어놓아야 한다")
	}
}

func TestFormatWithNoPeers(t *testing.T) {
	now := time.Now()
	out := Format(Status{PeerID: "srv-a", Since: now}, now)
	if !strings.Contains(out, "다른 상대가 없습니다") {
		t.Errorf("상대가 없다는 것을 알려야 한다:\n%s", out)
	}
}
