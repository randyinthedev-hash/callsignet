package guard

import (
	"net/netip"
	"testing"
)

func TestParseLocal(t *testing.T) {
	cases := []struct {
		in   string
		addr string
		port int
	}{
		// /proc/net은 주소를 4바이트씩 뒤집어 적는다.
		{"00000000:0016", "0.0.0.0", 22},
		{"0100007F:0035", "127.0.0.1", 53},
		{"0200910A:1F90", "10.145.0.2", 8080},
		// IPv6도 4바이트씩 뒤집혀 있다. ::1이다.
		{"00000000000000000000000001000000:0016", "::1", 22},
	}
	for _, c := range cases {
		addr, port, ok := parseLocal(c.in)
		if !ok {
			t.Errorf("%s를 읽지 못했다", c.in)
			continue
		}
		if addr.String() != c.addr || port != c.port {
			t.Errorf("%s: %s:%d여야 하는데 %s:%d", c.in, c.addr, c.port, addr, port)
		}
	}
	if _, _, ok := parseLocal("이건아니다"); ok {
		t.Error("읽을 수 없는 것을 읽었다고 한다")
	}
}

// 루프백에만 붙은 소켓은 밖에서 닿지 못하므로 세지 않는다.
func TestLoopbackIsNotExposed(t *testing.T) {
	addr, _, _ := parseLocal("0100007F:0035")
	if !addr.IsLoopback() {
		t.Error("127.0.0.1을 루프백으로 보지 않는다")
	}
	addr, _, _ = parseLocal("00000000:0016")
	if addr.IsLoopback() {
		t.Error("0.0.0.0을 루프백으로 본다")
	}
}

// 이 머신에서 실제로 읽어 본다. 무엇이 나올지는 머신마다 다르므로 모양만 본다.
func TestExposedReadsProcNet(t *testing.T) {
	got, err := Exposed(map[int]bool{}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if p.Proto != "tcp" && p.Proto != "udp" {
			t.Errorf("모르는 프로토콜이다: %s", p.Proto)
		}
		if p.Num <= 0 || p.Num > 65535 {
			t.Errorf("포트가 범위를 벗어났다: %d", p.Num)
		}
	}
}
