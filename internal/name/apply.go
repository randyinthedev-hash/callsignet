package name

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
// tunnelIP는 systemd-resolved에 등록할 주소다. resolved는 루프백 주소를
// 받아 주지 않으므로 터널 인터페이스에 붙은 주소를 쓴다. csa는 그 주소에서도
// 질의를 받는다.
func Apply(iface, listenAddr, tunnelIP, domain, revZone string, logf func(string, ...any)) (*Takeover, error) {
	ap, err := netip.ParseAddrPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("dns.listen을 읽을 수 없다: %s", listenAddr)
	}
	listenIP := ap.Addr().String()

	link, _ := os.Readlink(resolvConf)
	content, _ := os.ReadFile(resolvConf)
	_, lookErr := exec.LookPath("resolvectl")
	m := Detect(link, string(content), lookErr == nil)
	t := &Takeover{Manager: m, logf: logf}

	switch m {
	case ManagerResolved:
		if err := t.applyResolved(iface, tunnelIP, domain, revZone); err != nil {
			// 걸지 못했으면 파일을 직접 고쳐 본다. 여기서 멈추면 csa가 아예
			// 뜨지 않으므로, 물러설 자리를 두고 무엇이 막혔는지 적는다.
			logf("systemd-resolved에 걸지 못했습니다. 파일을 직접 고칩니다: %v", err)
			t.Manager = ManagerFile
			if err := t.applyFile(listenIP, domain); err != nil {
				return nil, err
			}
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
	logf("이름 해석 설정을 걸었습니다. 관리 주체는 %s입니다.", t.Manager)
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
	path, err := resolvTarget(resolvConf)
	if err != nil {
		return err
	}
	if path != resolvConf {
		t.logf("%s는 %s를 가리킵니다. 그 파일에 씁니다. 관리하는 것이 있으면 되돌릴 수 있습니다.",
			resolvConf, path)
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s를 읽지 못했다: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(ResolvConf(string(old), listenIP, domain)), 0o644); err != nil {
		return fmt.Errorf("%s를 쓰지 못했다: %w", path, err)
	}
	// 되돌릴 때는 csa가 넣은 줄만 지운다. 통째로 되쓰면 csa가 도는 동안 다른
	// 것이 고친 내용을 없앤다.
	t.restore = func() error {
		cur, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s를 읽지 못했다: %w", path, err)
		}
		return os.WriteFile(path, []byte(Restore(string(cur), listenIP, domain)), 0o644)
	}
	return nil
}

// resolvTarget은 실제로 쓸 파일의 경로를 돌려준다.
//
// 심볼릭 링크면 그것이 가리키는 파일을 돌려준다. 링크 자체를 갈아치우면
// 시스템의 다른 설정을 망가뜨린다. 네트워크 네임스페이스는 링크가 가리키는
// 자리에 다른 파일을 붙여 두므로, 링크를 갈아치우면 그 파일에 닿지도 못한다.
func resolvTarget(path string) (string, error) {
	link, err := os.Readlink(path)
	if err != nil {
		return path, nil // 심볼릭 링크가 아니다
	}
	if filepath.IsAbs(link) {
		return link, nil
	}
	return filepath.Clean(filepath.Join(filepath.Dir(path), link)), nil
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
