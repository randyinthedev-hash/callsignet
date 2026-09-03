package wgdev

import (
	"strings"
	"testing"

	"github.com/randyinthedev-hash/callsignet/internal/config"
)

// keyC는 시험에서 키를 바꿀 때 쓴다. 32바이트를 base64로 적은 것이다.
const keyC = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="

// 바뀌지 않았으면 wg에 한 줄도 걸지 않아야 한다. 다시 걸면 wg가 들고 있던
// 관측한 접속 주소를 설정에 적힌 값으로 되돌린다.
func TestUAPIReloadSaysNothingWhenNothingChanged(t *testing.T) {
	got, err := UAPIReload(sample(), sample())
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("한 줄도 없어야 하는데:\n%s", got)
	}
}

func TestUAPIReloadAddsPeer(t *testing.T) {
	cur := sample()
	cur.Peers = append(cur.Peers, config.Peer{
		PeerID: "srv-c", PublicKey: keyC, TunnelIP: "10.91.0.3",
		Endpoints: []string{"10.0.5.3:51820"},
	})
	got, err := UAPIReload(sample(), cur)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"public_key=3132333435363738393031323334353637383930313233343536373839303132",
		"allowed_ip=10.91.0.3/32", "endpoint=10.0.5.3:51820",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("없다: %s\n%s", want, got)
		}
	}
	if strings.Contains(got, "remove=true") {
		t.Errorf("지울 것이 없는데 지우려 한다:\n%s", got)
	}
	// 그대로인 상대는 건드리지 않는다.
	if strings.Count(got, "public_key=") != 1 {
		t.Errorf("새 상대 하나만 걸어야 하는데:\n%s", got)
	}
}

func TestUAPIReloadRemovesPeer(t *testing.T) {
	cur := sample()
	cur.Peers = cur.Peers[:1] // srv-b를 뺀다
	got, err := UAPIReload(sample(), cur)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "remove=true") {
		t.Errorf("지우라고 해야 하는데:\n%s", got)
	}
	if strings.Contains(got, "allowed_ip=") {
		t.Errorf("지우면서 다시 걸면 안 된다:\n%s", got)
	}
}

func TestUAPIReloadUpdatesEndpoint(t *testing.T) {
	cur := sample()
	cur.Peers[1].Endpoints = []string{"10.0.5.99:51820"}
	got, err := UAPIReload(sample(), cur)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "endpoint=10.0.5.99:51820") {
		t.Errorf("새 접속 주소를 걸어야 하는데:\n%s", got)
	}
	if strings.Contains(got, "remove=true") {
		t.Errorf("키가 그대로면 지우면 안 된다:\n%s", got)
	}
}

// 공개키가 바뀐 상대는 wg에게 다른 상대다. 옛 키를 먼저 지워야 한다.
func TestUAPIReloadReplacesPeerWhenKeyChanged(t *testing.T) {
	cur := sample()
	cur.Peers[1].PublicKey = keyC
	got, err := UAPIReload(sample(), cur)
	if err != nil {
		t.Fatal(err)
	}
	rm := strings.Index(got, "remove=true")
	add := strings.Index(got, "allowed_ip=")
	if rm < 0 || add < 0 {
		t.Fatalf("지우고 넣어야 하는데:\n%s", got)
	}
	if rm > add {
		t.Errorf("지우는 것이 먼저여야 하는데:\n%s", got)
	}
}

// 자기 자신은 상대가 아니므로 자기 항목이 바뀌어도 wg에 걸 것이 없다.
func TestUAPIReloadSkipsSelf(t *testing.T) {
	cur := sample()
	cur.Peers[0].Endpoints = []string{"10.0.5.77:51820"}
	got, err := UAPIReload(sample(), cur)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("한 줄도 없어야 하는데:\n%s", got)
	}
}

func TestUAPIReloadRejectsBadKey(t *testing.T) {
	cur := sample()
	cur.Peers[1].PublicKey = "짧다"
	if _, err := UAPIReload(sample(), cur); err == nil {
		t.Error("길이가 틀린 키는 거부해야 한다")
	}
}
