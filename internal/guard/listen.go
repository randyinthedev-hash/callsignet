package guard

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Port는 밖으로 열려 있는 포트 하나다.
type Port struct {
	Proto string
	Num   int
}

func (p Port) String() string { return fmt.Sprintf("%s %d", p.Proto, p.Num) }

// procNet은 읽을 파일과 그 파일이 담는 프로토콜이다.
var procNet = []struct {
	path  string
	proto string
	// state는 그 프로토콜에서 「듣고 있다」를 뜻하는 값이다. TCP는 LISTEN이고
	// UDP에는 그런 상태가 없어 소켓이 열려 있다는 값을 쓴다.
	state string
}{
	{"/proc/net/tcp", "tcp", "0A"},
	{"/proc/net/tcp6", "tcp", "0A"},
	{"/proc/net/udp", "udp", "07"},
	{"/proc/net/udp6", "udp", "07"},
}

// Exposed는 이 머신에서 밖으로 열려 있는 포트를 찾는다.
//
// known에 있는 포트와, 루프백이나 selfIP에만 붙어 있는 소켓은 빼고 돌려준다.
// 그 둘은 밖에서 닿지 못하거나 csa가 이미 아는 것이다.
func Exposed(known map[int]bool, selfIP netip.Addr) ([]Port, error) {
	seen := map[Port]bool{}
	var out []Port
	for _, f := range procNet {
		lines, err := os.ReadFile(f.path)
		if err != nil {
			continue // 그 계열이 꺼져 있으면 파일이 없다
		}
		for _, line := range strings.Split(string(lines), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != f.state {
				continue
			}
			addr, port, ok := parseLocal(fields[1])
			if !ok || known[port] {
				continue
			}
			if addr.IsLoopback() || (selfIP.IsValid() && addr == selfIP) {
				continue
			}
			p := Port{Proto: f.proto, Num: port}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sortPorts(out)
	return out, nil
}

// parseLocal은 /proc/net이 적는 주소를 읽는다. 모양은 16진수 주소와 포트를
// 콜론으로 이은 것이다. 주소는 4바이트씩 뒤집혀 있다.
func parseLocal(s string) (netip.Addr, int, bool) {
	h, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, false
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, false
	}
	return addr.Unmap(), int(port), true
}

func sortPorts(p []Port) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && less(p[j], p[j-1]); j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

func less(a, b Port) bool {
	if a.Proto != b.Proto {
		return a.Proto < b.Proto
	}
	return a.Num < b.Num
}
