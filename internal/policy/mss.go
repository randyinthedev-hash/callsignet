package policy

import "encoding/binary"

// mssOption은 TCP 옵션에서 최대 세그먼트 크기를 가리키는 번호다.
const mssOption = 2

// ClampMSS는 TCP SYN에 실린 최대 세그먼트 크기를 max 이하로 깎는다. 깎았으면
// 참을 돌려준다.
//
// SYN을 보내는 쪽은 이 옵션으로 「나는 이만큼까지 받을 수 있다」고 알린다. 터널이
// 나를 수 있는 크기보다 크게 알리면 상대가 그만큼 큰 세그먼트를 보내고, 그것이
// 터널을 지나면서 조각이 나거나 버려진다. 중간 방화벽이 ICMP를 버리면 경로 MTU
// 발견도 되지 않아 조용히 사라진다.
//
// 앱이 이 머신에서 직접 돌면 커널이 터널 경로의 MTU를 보고 알아서 정하므로 깎을
// 일이 드물다. 경로에 advmss가 걸려 있거나 앱이 스스로 크기를 정한 경우에 깎는다.
//
// 검사합은 바꾼 낱말만큼만 고친다.
func ClampMSS(pkt []byte, max uint16) bool {
	if max == 0 || len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	if pkt[9] != protoTCP {
		return false
	}
	// 조각난 패킷의 뒷조각에는 TCP 헤더가 없다.
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return false
	}
	tcp := pkt[ihl:]
	const synFlag = 0x02
	if tcp[13]&synFlag == 0 {
		return false // SYN에만 이 옵션이 실린다
	}
	off := int(tcp[12]>>4) * 4
	if off < 20 || off > len(tcp) {
		return false
	}

	opts := tcp[20:off]
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0:
			return false // 옵션 끝
		case 1:
			i++ // 자리 채우기
			continue
		}
		if i+1 >= len(opts) {
			return false
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			return false
		}
		if opts[i] == mssOption && l == 4 {
			cur := binary.BigEndian.Uint16(opts[i+2:])
			if cur <= max {
				return false
			}
			binary.BigEndian.PutUint16(opts[i+2:], max)
			fixChecksum(tcp[16:18], cur, max)
			return true
		}
		i += l
	}
	return false
}

// fixChecksum은 16비트 낱말 하나가 바뀐 만큼만 검사합을 고친다. RFC 1624가 적은
// 방식이다. 패킷 전체를 다시 더하지 않아도 된다.
func fixChecksum(sum []byte, old, cur uint16) {
	x := uint32(^binary.BigEndian.Uint16(sum)) + uint32(^old) + uint32(cur)
	for x>>16 != 0 {
		x = (x & 0xffff) + (x >> 16)
	}
	binary.BigEndian.PutUint16(sum, ^uint16(x))
}
