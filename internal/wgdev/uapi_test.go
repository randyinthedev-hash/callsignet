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
