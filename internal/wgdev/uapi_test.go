package wgdev

import (
	"strings"
	"testing"

	"github.com/randyinthedev-hash/callsignet/internal/config"
)

const (
	keyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	keyB = "//////////////////////////////////////////8="
)

func sample() *config.Config {
	return &config.Config{
		Self: config.Self{PeerID: "srv-a", ListenPort: 51820},
		Peers: []config.Peer{
			{PeerID: "srv-a", PublicKey: keyA, TunnelIP: "10.91.0.1"},
			{PeerID: "srv-b", PublicKey: keyB, TunnelIP: "10.91.0.2",
				Endpoints: []string{"10.0.5.2:51820"}},
		},
	}
}

func TestUAPIConfig(t *testing.T) {
	got, err := UAPIConfig(sample(), keyA)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"private_key=" + strings.Repeat("00", 32),
		"listen_port=51820",
		"replace_peers=true",
		"public_key=" + strings.Repeat("ff", 32),
		"allowed_ip=10.91.0.2/32",
		"endpoint=10.0.5.2:51820",
		"persistent_keepalive_interval=25",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%q가 없다. 나온 것:\n%s", w, got)
		}
	}
}

func TestUAPIConfigSkipsSelf(t *testing.T) {
	got, err := UAPIConfig(sample(), keyA)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(got, "public_key="); n != 1 {
		t.Fatalf("자기 자신을 상대로 넣었다. public_key가 %d개", n)
	}
	if strings.Contains(got, "allowed_ip=10.91.0.1/32") {
		t.Fatal("자기 터널 IP를 허용 목록에 넣었다")
	}
}

func TestUAPIConfigRejectsBadKey(t *testing.T) {
	c := sample()
	c.Peers[1].PublicKey = "짧다"
	if _, err := UAPIConfig(c, keyA); err == nil {
		t.Fatal("잘못된 공개키를 받아들였다")
	}
	if _, err := UAPIConfig(sample(), "AAAA"); err == nil {
		t.Fatal("길이가 모자란 개인키를 받아들였다")
	}
}

func TestEndpointFor(t *testing.T) {
	state := "private_key=00\n" +
		"public_key=aa\nendpoint=10.0.5.2:51820\nlast_handshake_time_sec=1\n" +
		"public_key=bb\nendpoint=10.0.5.3:51820\n"
	if got := endpointFor(state, "bb"); got != "10.0.5.3:51820" {
		t.Fatalf("10.0.5.3:51820이어야 하는데 %q", got)
	}
	if got := endpointFor(state, "cc"); got != "" {
		t.Fatalf("모르는 키에는 빈 값이어야 하는데 %q", got)
	}
	// 접속 주소가 아직 없는 상대다.
	if got := endpointFor("public_key=dd\n", "dd"); got != "" {
		t.Fatalf("빈 값이어야 하는데 %q", got)
	}
}
