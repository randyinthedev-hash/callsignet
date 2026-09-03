package name

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"time"
)

const resolvConf = "/etc/resolv.conf"

// Takeover는 csa가 걸어 둔 이름 해석 설정이다. Close가 되돌린다.
type Takeover struct {
	Manager Manager
	restore func() error
	logf    func(string, ...any)
}

// Apply는 내부 도메인 질의가 csa에게 오도록 시스템 설정을 건다.
//
// 관리 주체를 판별해 거기에 맞춰 건다. systemd-resolved가 관리하면 인터페이스에
// 도메인을 등록하고, 아무도 관리하지 않으면 /etc/resolv.conf를 직접 고친다.
func Apply(iface, listenAddr, domain, revZone string, logf func(string, ...any)) (*Takeover, error) {
	ap, err := netip.ParseAddrPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("dns.listen을 읽을 수 없다: %s", listenAddr)
	}
	listenIP := ap.Addr().String()

	link, _ := os.Readlink(resolvConf)
	_, lookErr := exec.LookPath("resolvectl")
	m := Detect(link, lookErr == nil)
	t := &Takeover{Manager: m, logf: logf}

	switch m {
	case ManagerResolved:
		if err := t.applyResolved(iface, listenIP, domain, revZone); err != nil {
			return nil, err
		}
	case ManagerNetworkManager:
		// NetworkManager의 전역 DNS 설정은 백엔드에 따라 무시된다. 그래서 파일을
		// 직접 고치되, NetworkManager가 되돌릴 수 있다는 것을 알린다.
		logf("NetworkManager가 %s를 관리합니다. csa가 직접 고치지만 NetworkManager가"+
			" 되돌릴 수 있습니다. 그때는 systemd-resolved를 쓰도록 바꾸십시오.", resolvConf)
		fallthrough
	default:
		if err := t.applyFile(listenIP, domain); err != nil {
			return nil, err
		}
	}
	logf("이름 해석 설정을 걸었습니다. 관리 주체는 %s입니다.", m)
	return t, nil
}

// Close는 걸어 둔 설정을 되돌린다.
func (t *Takeover) Close() {
	if t == nil || t.restore == nil {
		return
	}
	if err := t.restore(); err != nil {
		t.logf("이름 해석 설정을 되돌리지 못했습니다: %v", err)
		return
	}
	t.logf("이름 해석 설정을 되돌렸습니다.")
}

func (t *Takeover) applyResolved(iface, listenIP, domain, revZone string) error {
	for _, args := range ResolvedArgs(iface, listenIP, domain, revZone) {
		if out, err := exec.Command("resolvectl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("resolvectl %v에 실패했다: %v (%s)", args, err, out)
		}
	}
	// 인터페이스가 사라지면 이 설정도 함께 사라지므로 되돌릴 것이 없다.
	return nil
}

func (t *Takeover) applyFile(listenIP, domain string) error {
	old, err := os.ReadFile(resolvConf)
	if err != nil {
		return fmt.Errorf("%s를 읽지 못했다: %w", resolvConf, err)
	}
	link, _ := os.Readlink(resolvConf)

	if err := writeResolvConf(ResolvConf(string(old), listenIP, domain)); err != nil {
		return err
	}
	t.restore = func() error {
		if link != "" {
			// 원래 심볼릭 링크였다면 그대로 되돌린다.
			if err := os.Remove(resolvConf); err != nil {
				return err
			}
			return os.Symlink(link, resolvConf)
		}
		return writeResolvConf(string(old))
	}
	return nil
}

// writeResolvConf는 파일을 통째로 바꾼다.
//
// 먼저 임시 파일을 만들어 이름을 바꾸는 방식을 쓴다. 읽는 쪽이 반쯤 쓰인 파일을
// 보지 않게 하려는 것이다. 그런데 그 파일이 bind mount로 붙어 있으면 이름을
// 바꿀 수 없다. 네트워크 네임스페이스 안이 그렇다. 그때는 제자리에 쓴다.
func writeResolvConf(content string) error {
	tmp := resolvConf + ".callsignet"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err == nil {
		if err := os.Rename(tmp, resolvConf); err == nil {
			return nil
		}
		os.Remove(tmp)
	}
	if err := os.WriteFile(resolvConf, []byte(content), 0o644); err != nil {
		return fmt.Errorf("%s를 쓰지 못했다: %w", resolvConf, err)
	}
	return nil
}

// Verify는 설정이 실제로 먹었는지 스스로 확인한다. 자기 머신 이름을 시스템
// 경로로 물어 자기 터널 IP가 나오는지 본다. 조용히 실패하면 앱이 이름을 찾지
// 못하는 것으로만 드러나 원인을 찾기 어렵다.
func Verify(machineName string, want netip.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	r := &net.Resolver{PreferGo: true}
	addrs, err := r.LookupHost(ctx, machineName)
	if err != nil {
		return fmt.Errorf("%s를 시스템 경로로 찾지 못했다: %w", machineName, err)
	}
	for _, a := range addrs {
		if a == want.String() {
			return nil
		}
	}
	return fmt.Errorf("답이 다르다: %s를 물었더니 %v (기대 %s)", machineName, addrs, want)
}
