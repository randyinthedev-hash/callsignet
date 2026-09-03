package policy

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// ipv4는 시험에 쓸 IPv4 패킷을 만든다.
func ipv4(src, dst string, proto uint8, sport, dport uint16, fragOffset uint16) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[6:8], fragOffset)
	b[9] = proto
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	return b
}

func TestParse(t *testing.T) {
	p, ok := Parse(ipv4("10.91.0.1", "10.91.0.2", protoTCP, 40000, 8080, 0))
	if !ok {
		t.Fatal("읽지 못했다")
	}
	if p.Src.String() != "10.91.0.1" || p.Dst.String() != "10.91.0.2" {
		t.Fatalf("주소가 틀렸다: %v", p)
	}
	if p.SrcPort != 40000 || p.DstPort != 8080 || !p.HasPorts() {
		t.Fatalf("포트가 틀렸다: %v", p)
	}
}

func TestParseRejectsNonIPv4(t *testing.T) {
	for _, b := range [][]byte{
		{}, {0x45}, // 너무 짧다
		{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // IPv6
	} {
		if _, ok := Parse(b); ok {
			t.Errorf("읽으면 안 된다: %v", b)
		}
	}
}

func TestParseSkipsPortsOnLaterFragment(t *testing.T) {
	// 조각난 패킷의 뒷조각에는 포트가 없다. 앞에 있는 값을 포트로 읽으면 안 된다.
	p, ok := Parse(ipv4("10.91.0.1", "10.91.0.2", protoTCP, 40000, 8080, 185))
	if !ok {
		t.Fatal("읽지 못했다")
	}
	if p.DstPort != 0 {
		t.Fatalf("뒷조각에서 포트를 읽었다: %d", p.DstPort)
	}
}

func TestParseICMPHasNoPorts(t *testing.T) {
	p, _ := Parse(ipv4("10.91.0.1", "10.91.0.2", protoICMP, 0, 0, 0))
	if p.HasPorts() {
		t.Fatal("ICMP에 포트가 있다고 보았다")
	}
}

func TestRejectICMP(t *testing.T) {
	orig := ipv4("10.91.0.1", "10.91.0.9", protoTCP, 40000, 8080, 0)
	out := RejectICMP(orig, netip.MustParseAddr("10.91.0.1"))
	if out == nil {
		t.Fatal("만들지 못했다")
	}
	p, ok := Parse(out)
	if !ok || p.Proto != protoICMP {
		t.Fatalf("ICMP가 아니다: %v", p)
	}
	// 원래 보낸 쪽에게 돌아가야 한다.
	if p.Dst.String() != "10.91.0.1" {
		t.Fatalf("보낸 쪽에게 가야 하는데 %s", p.Dst)
	}
	if out[20] != 3 || out[21] != 13 {
		t.Fatalf("관리자가 막았다는 뜻이어야 하는데 %d/%d", out[20], out[21])
	}
	// 원래 패킷의 머리를 담아야 앱의 커널이 어느 연결인지 안다.
	if string(out[28:28+20]) != string(orig[:20]) {
		t.Fatal("원래 패킷의 IP 헤더를 담지 않았다")
	}
	if checksum(out[:20]) != 0 {
		t.Fatal("IP 검사합이 맞지 않는다")
	}
}
