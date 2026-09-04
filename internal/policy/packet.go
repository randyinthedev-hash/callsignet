package policy

import (
	"encoding/binary"
	"net/netip"
)

// 프로토콜 번호.
const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// Packet은 IPv4 패킷에서 판단에 쓰는 값만 뽑아낸 것이다.
type Packet struct {
	Src, Dst netip.Addr
	Proto    uint8
	SrcPort  uint16
	DstPort  uint16
}

// Parse는 IPv4 패킷을 읽는다. IPv4가 아니거나 잘린 패킷이면 false를 돌려준다.
func Parse(b []byte) (Packet, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return Packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return Packet{}, false
	}
	p := Packet{
		Src:   netip.AddrFrom4([4]byte(b[12:16])),
		Dst:   netip.AddrFrom4([4]byte(b[16:20])),
		Proto: b[9],
	}
	// 조각난 패킷의 뒷조각에는 포트가 없다. 첫 조각만 포트를 읽는다.
	fragOffset := binary.BigEndian.Uint16(b[6:8]) & 0x1fff
	if fragOffset == 0 && (p.Proto == protoTCP || p.Proto == protoUDP) && len(b) >= ihl+4 {
		p.SrcPort = binary.BigEndian.Uint16(b[ihl : ihl+2])
		p.DstPort = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
	}
	return p, true
}

// HasPorts는 그 패킷에 포트가 있는지 본다. ICMP처럼 포트가 없는 것도 있다.
func (p Packet) HasPorts() bool { return p.Proto == protoTCP || p.Proto == protoUDP }

// RejectICMP는 「관리자가 막았다」는 뜻의 ICMP 응답을 만든다. 앱이 연결 시간을
// 다 기다리지 않고 곧바로 실패를 보게 하려는 것이다.
//
// 원래 패킷의 IP 헤더와 그 뒤 8바이트를 담아 돌려준다. 앱의 커널이 그것을 보고
// 어느 연결에 대한 응답인지 안다.
//
// 출발지는 원래 패킷의 목적지로 적는다. 이 머신의 터널 IP로 적으면 출발지와
// 목적지가 둘 다 이 머신의 주소인 패킷이 TUN 인터페이스로 들어온다. rp_filter가
// 엄격한 머신은 그것을 버리므로 앱이 아무것도 받지 못한다. 원래 목적지는 터널
// 대역 안이고 그 대역으로 가는 경로가 TUN 인터페이스이므로 버려지지 않는다.
func RejectICMP(orig []byte) []byte {
	if len(orig) < 20 {
		return nil
	}
	ihl := int(orig[0]&0x0f) * 4
	quote := ihl + 8
	if quote > len(orig) {
		quote = len(orig)
	}
	// ICMP 부분: 종류 3, 코드 13(관리자가 막음), 검사합, 쓰지 않는 4바이트.
	icmp := make([]byte, 8+quote)
	icmp[0], icmp[1] = 3, 13
	copy(icmp[8:], orig[:quote])
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))

	total := 20 + len(icmp)
	out := make([]byte, total)
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out[8] = 64 // TTL
	out[9] = protoICMP
	copy(out[12:16], orig[16:20]) // 원래 패킷의 목적지가 이 응답의 출발지다
	copy(out[16:20], orig[12:16]) // 원래 보낸 쪽에게 돌려준다
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	copy(out[20:], icmp)
	return out
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
