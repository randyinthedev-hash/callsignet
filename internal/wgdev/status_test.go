package wgdev

import (
	"testing"
	"time"
)

// wg가 IpcGet으로 내놓는 모양이다. 첫 세 줄은 인터페이스 자신의 값이고 그
// 뒤가 상대 둘이다.
const sampleState = `private_key=0000000000000000000000000000000000000000000000000000000000000001
listen_port=51820
fwmark=0
public_key=aaaa000000000000000000000000000000000000000000000000000000000001
endpoint=10.90.0.2:51820
last_handshake_time_sec=1756900000
last_handshake_time_nsec=500000000
tx_bytes=3800
rx_bytes=4200
persistent_keepalive_interval=25
allowed_ip=10.91.0.2/32
public_key=bbbb000000000000000000000000000000000000000000000000000000000002
last_handshake_time_sec=0
last_handshake_time_nsec=0
tx_bytes=0
rx_bytes=0
allowed_ip=10.91.0.3/32
protocol_version=1
errno=0
`

func TestParseStatus(t *testing.T) {
	got := parseStatus(sampleState)
	if len(got) != 2 {
		t.Fatalf("상대 둘이어야 하는데 %d개", len(got))
	}

	a := got["aaaa000000000000000000000000000000000000000000000000000000000001"]
	if a.Endpoint != "10.90.0.2:51820" {
		t.Errorf("접속 주소가 다르다: %s", a.Endpoint)
	}
	if a.RxBytes != 4200 || a.TxBytes != 3800 {
		t.Errorf("바이트 수가 다르다: 받음 %d, 보냄 %d", a.RxBytes, a.TxBytes)
	}
	want := time.Unix(1756900000, 500000000)
	if !a.Handshake.Equal(want) {
		t.Errorf("handshake 시각이 다르다: %v", a.Handshake)
	}

	// 아직 한 번도 세션을 맺지 않은 상대는 시각이 비어 있어야 한다. wg는 그런
	// 상대에게 0을 내놓는데, 그것을 1970년으로 읽으면 안 된다.
	b := got["bbbb000000000000000000000000000000000000000000000000000000000002"]
	if !b.Handshake.IsZero() {
		t.Errorf("세션을 맺지 않았으면 시각이 비어야 하는데 %v", b.Handshake)
	}
	if b.Endpoint != "" {
		t.Errorf("접속 주소가 없어야 하는데 %s", b.Endpoint)
	}
}

// 첫 public_key= 줄보다 앞에 있는 값은 인터페이스 자신의 것이므로 어느
// 상대에게도 붙지 않아야 한다.
func TestParseStatusDropsInterfaceValues(t *testing.T) {
	got := parseStatus("listen_port=51820\nfwmark=0\n")
	if len(got) != 0 {
		t.Errorf("상대가 없어야 하는데 %d개", len(got))
	}
}
