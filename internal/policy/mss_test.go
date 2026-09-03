package policy

import (
	"encoding/binary"
	"testing"
)

// SYN 하나를 만든다. opts에 TCP 옵션을 그대로 넣는다.
func syn(opts []byte, flags byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, 1) // 자리 채우기
	}
	pkt := make([]byte, 20+20+len(opts))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[9] = protoTCP
	copy(pkt[12:16], []byte{10, 91, 0, 1})
	copy(pkt[16:20], []byte{10, 91, 0, 2})

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:], 40000) // 출발지 포트
	binary.BigEndian.PutUint16(tcp[2:], 8080)  // 목적지 포트
	tcp[12] = byte((20+len(opts))/4) << 4
	tcp[13] = flags
	copy(tcp[20:], opts)
	setChecksum(pkt)
	return pkt
}

// setChecksum은 TCP 검사합을 제대로 계산해 넣는다. 깎은 뒤에도 맞는지 보려면
// 처음에 맞아 있어야 한다.
func setChecksum(pkt []byte) {
	tcp := pkt[20:]
	tcp[16], tcp[17] = 0, 0
	var sum uint32
	// 의사 헤더: 출발지, 목적지, 0, 프로토콜, TCP 길이.
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	sum += uint32(protoTCP) + uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:], ^uint16(sum))
}

// checksumOK는 검사합이 맞는지 본다. 맞으면 다시 더한 값이 0xffff가 된다.
func checksumOK(pkt []byte) bool {
	tcp := pkt[20:]
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	sum += uint32(protoTCP) + uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

func mssOf(pkt []byte) uint16 {
	tcp := pkt[20:]
	off := int(tcp[12]>>4) * 4
	opts := tcp[20:off]
	for i := 0; i+1 < len(opts); {
		if opts[i] == 1 {
			i++
			continue
		}
		if opts[i] == mssOption {
			return binary.BigEndian.Uint16(opts[i+2:])
		}
		i += int(opts[i+1])
	}
	return 0
}

func TestClampMSSCutsAndFixesChecksum(t *testing.T) {
	pkt := syn([]byte{2, 4, 0x05, 0xb4}, 0x02) // MSS 1460
	if !checksumOK(pkt) {
		t.Fatal("시험이 만든 패킷의 검사합부터 틀렸다")
	}
	if !ClampMSS(pkt, 1380) {
		t.Fatal("깎아야 하는데 깎지 않았다")
	}
	if got := mssOf(pkt); got != 1380 {
		t.Errorf("1380이어야 하는데 %d", got)
	}
	if !checksumOK(pkt) {
		t.Error("깎고 나서 검사합이 틀렸다")
	}
}

func TestClampMSSLeavesSmallEnoughAlone(t *testing.T) {
	pkt := syn([]byte{2, 4, 0x05, 0x64}, 0x02) // MSS 1380
	if ClampMSS(pkt, 1380) {
		t.Error("한도와 같은 값을 깎았다")
	}
	if got := mssOf(pkt); got != 1380 {
		t.Errorf("건드리지 말아야 하는데 %d", got)
	}
}

// 옵션이 여럿이어도 MSS를 찾아내야 한다. 앞에 자리 채우기와 다른 옵션을 둔다.
func TestClampMSSFindsOptionAmongOthers(t *testing.T) {
	// 1: 자리 채우기, 3/3: 창 크기 조절, 2/4: MSS
	pkt := syn([]byte{1, 3, 3, 7, 2, 4, 0x05, 0xb4}, 0x02)
	if !ClampMSS(pkt, 1300) {
		t.Fatal("다른 옵션 뒤에 있는 MSS를 찾지 못했다")
	}
	if got := mssOf(pkt); got != 1300 {
		t.Errorf("1300이어야 하는데 %d", got)
	}
	if !checksumOK(pkt) {
		t.Error("검사합이 틀렸다")
	}
}

func TestClampMSSIgnoresWhatItShould(t *testing.T) {
	// SYN이 아니면 이 옵션이 실리지 않는다.
	if ClampMSS(syn([]byte{2, 4, 0x05, 0xb4}, 0x10), 1380) {
		t.Error("SYN이 아닌 것을 건드렸다")
	}
	// MSS 옵션이 없다.
	if ClampMSS(syn([]byte{1, 3, 3, 7}, 0x02), 1380) {
		t.Error("MSS 옵션이 없는데 깎았다고 한다")
	}
	// TCP가 아니다.
	pkt := syn([]byte{2, 4, 0x05, 0xb4}, 0x02)
	pkt[9] = protoUDP
	if ClampMSS(pkt, 1380) {
		t.Error("TCP가 아닌 것을 건드렸다")
	}
	// 조각난 패킷의 뒷조각이다.
	pkt = syn([]byte{2, 4, 0x05, 0xb4}, 0x02)
	binary.BigEndian.PutUint16(pkt[6:], 0x0001)
	if ClampMSS(pkt, 1380) {
		t.Error("뒷조각을 건드렸다")
	}
	// 한도가 0이면 깎지 않는다.
	if ClampMSS(syn([]byte{2, 4, 0x05, 0xb4}, 0x02), 0) {
		t.Error("한도가 없는데 깎았다")
	}
	// 잘린 패킷.
	if ClampMSS([]byte{0x45, 0, 0, 4}, 1380) {
		t.Error("잘린 패킷을 건드렸다")
	}
}

// 길이가 틀린 옵션을 만나면 멈춘다. 무한히 돌면 안 된다.
func TestClampMSSStopsOnBadOption(t *testing.T) {
	if ClampMSS(syn([]byte{5, 0, 0, 0}, 0x02), 1380) {
		t.Error("길이가 틀린 옵션을 읽고 깎았다고 한다")
	}
	if ClampMSS(syn([]byte{5, 200, 0, 0}, 0x02), 1380) {
		t.Error("헤더 밖을 가리키는 옵션을 읽었다")
	}
}
