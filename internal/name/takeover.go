package name

import (
	"fmt"
	"strings"
)

// Manager는 그 머신에서 이름 해석 설정을 누가 쥐고 있는지 가린다.
type Manager int

const (
	// ManagerFile은 아무도 관리하지 않는 경우다. csa가 /etc/resolv.conf를 직접 고친다.
	ManagerFile Manager = iota
	// ManagerResolved는 systemd-resolved가 관리하는 경우다. csa가 내부 도메인만
	// 자기에게 보내도록 등록한다.
	ManagerResolved
	// ManagerNetworkManager는 NetworkManager가 관리하는 경우다.
	ManagerNetworkManager
)

func (m Manager) String() string {
	switch m {
	case ManagerResolved:
		return "systemd-resolved"
	case ManagerNetworkManager:
		return "NetworkManager"
	default:
		return "직접 관리"
	}
}

// ResolvedStub은 systemd-resolved가 질의를 받는 주소다.
const ResolvedStub = "127.0.0.53"

// Detect는 관리 주체를 가린다.
//
// 파일 내용을 먼저 본다. 앱이 실제로 어디에 묻는지가 거기 적혀 있기 때문이다.
// 심볼릭 링크가 어디를 가리키는지는 그다음에 본다. 링크만 보면 속을 수 있다.
// 네트워크 네임스페이스는 다른 파일을 그 자리에 붙이면서 링크는 그대로 두기
// 때문이다.
func Detect(link, content string, hasResolvectl bool) Manager {
	for _, up := range upstreams(content) {
		if up == ResolvedStub {
			return ManagerResolved
		}
	}
	if len(upstreams(content)) > 0 {
		// 다른 리졸버를 가리키고 있다. 그 파일을 우리가 고친다.
		return ManagerFile
	}
	switch {
	case strings.Contains(link, "systemd"):
		return ManagerResolved
	case strings.Contains(link, "NetworkManager"):
		return ManagerNetworkManager
	default:
		return ManagerFile
	}
}

// ResolvConf는 csa를 첫 줄에 둔 /etc/resolv.conf 내용을 만든다.
//
// 원래 리졸버를 둘째 줄에 남긴다. csa가 멈춰도 내부 도메인 밖의 이름 해석은
// 둘째 줄로 넘어가게 하려는 것이다. 내부 도메인은 그때 찾지 못하는데, csa가
// 없으면 어차피 연결하지 못하므로 그것이 맞는 동작이다.
func ResolvConf(old, listenIP, domain string) string {
	var b strings.Builder
	b.WriteString("# Callsignet이 고쳤습니다. csa가 멈추면 되돌립니다.\n")
	fmt.Fprintf(&b, "nameserver %s\n", listenIP)
	for _, up := range upstreams(old) {
		if up == listenIP {
			continue
		}
		fmt.Fprintf(&b, "nameserver %s\n", up)
	}
	fmt.Fprintf(&b, "search %s\n", domain)
	for _, line := range strings.Split(old, "\n") {
		// options와 그 밖의 줄은 그대로 옮긴다.
		if strings.HasPrefix(line, "options ") || strings.HasPrefix(line, "sortlist ") {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

// upstreams는 원래 파일에 적힌 리졸버 주소를 뽑아낸다.
func upstreams(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// ResolvedArgs는 systemd-resolved에 걸 명령의 인자를 만든다.
//
// 내부 도메인만 csa에게 보낸다. 역방향 구역도 함께 등록해야 한다. 역방향
// 질의는 내부 도메인이 아니라 in-addr.arpa 구역으로 가기 때문이다.
func ResolvedArgs(iface, listenIP, domain, revZone string) [][]string {
	return [][]string{
		{"dns", iface, listenIP},
		{"domain", iface, "~" + domain, "~" + revZone},
	}
}
