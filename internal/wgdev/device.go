//go:build linux

package wgdev

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/randyinthedev-hash/callsignet/internal/config"
	"github.com/randyinthedev-hash/callsignet/internal/policy"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Device는 csa가 만든 TUN 인터페이스와 그 위에서 도는 wg다.
type Device struct {
	Name string
	tun  tun.Device
	dev  *device.Device
	// pubOf는 peer-id로 그 상대의 공개키를 찾는다. wg에게 접속 주소를 물을 때 쓴다.
	pubOf map[string]string
}

// Open은 TUN 인터페이스를 만들고, 터널 IP와 경로와 MTU를 걸고, wg를 시작한다.
// 네트워크 관리 권한이 필요하다.
func Open(c *config.Config, logf func(string, ...any)) (*Device, error) {
	self := c.Find(c.Self.PeerID)
	if self == nil {
		return nil, fmt.Errorf("csa.toml의 peer-id가 peers.toml에 없다: %s", c.Self.PeerID)
	}
	privB64, err := readKey(c.Self.PrivateKey)
	if err != nil {
		return nil, err
	}
	uapi, err := UAPIConfig(c, privB64)
	if err != nil {
		return nil, err
	}

	mtu := c.Self.Tun.MTU
	if mtu == 0 {
		mtu = 1420
	}
	name := c.Self.Tun.Name
	if name == "" {
		name = "cs0"
	}

	rules, err := policy.New(c)
	if err != nil {
		return nil, err
	}

	raw, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("TUN 인터페이스를 만들지 못했다: %w", err)
	}
	real, err := raw.Name()
	if err != nil {
		raw.Close()
		return nil, err
	}
	// 감싸서 정책을 집행한다. wg가 읽는 자리가 나가는 쪽이고 쓰는 자리가 받는 쪽이다.
	out := &Device{Name: real, pubOf: map[string]string{}}
	known := map[string]bool{}
	for _, peer := range c.Peers {
		if peer.PeerID == c.Self.PeerID {
			continue
		}
		if hexKey, err := keyToHex(peer.PublicKey); err == nil {
			out.pubOf[peer.PeerID] = hexKey
		}
		for _, ep := range peer.Endpoints {
			known[ep] = true
		}
	}
	t := &filter{
		Device: raw, rules: rules, logf: logf, flows: newFlows(),
		observe: out.endpointOf,
	}

	// CSA_DEBUG를 켜면 wg가 handshake와 세션을 어떻게 다루는지 모두 적는다.
	verbose := func(f string, a ...any) {}
	if os.Getenv("CSA_DEBUG") != "" {
		verbose = func(f string, a ...any) { logf("wg: "+f, a...) }
	}
	d := device.NewDevice(t, newBind(known, logf), &device.Logger{
		Verbosef: verbose,
		Errorf:   func(f string, a ...any) { logf("wg 오류: "+f, a...) },
	})
	if err := d.IpcSet(uapi); err != nil {
		d.Close()
		return nil, fmt.Errorf("wg 설정을 걸지 못했다: %w", err)
	}
	if err := d.Up(); err != nil {
		d.Close()
		return nil, fmt.Errorf("wg를 시작하지 못했다: %w", err)
	}
	if err := configureLink(real, self.TunnelIP, c.Self.TunnelCIDR, mtu); err != nil {
		d.Close()
		return nil, err
	}
	logf("TUN 인터페이스 %s를 열었습니다. 터널 IP는 %s입니다.", real, self.TunnelIP)
	out.tun, out.dev = t, d
	return out, nil
}

// endpointOf는 그 상대에게서 패킷이 실제로 온 주소를 wg에게 물어 돌려준다.
// wg가 복호화하면서 짝을 맞춰 둔 값이다. 인증을 통과한 패킷일 때만 갱신되므로
// 아무나 이 값을 바꿀 수 없다.
func (d *Device) endpointOf(peerID string) string {
	pub, ok := d.pubOf[peerID]
	if !ok || d.dev == nil {
		return ""
	}
	state, err := d.dev.IpcGet()
	if err != nil {
		return ""
	}
	return endpointFor(state, pub)
}

// endpointFor는 wg가 내놓은 상태에서 그 공개키의 접속 주소를 찾는다.
func endpointFor(state, pubHex string) string {
	var cur string
	for _, line := range strings.Split(state, "\n") {
		switch {
		case strings.HasPrefix(line, "public_key="):
			cur = strings.TrimPrefix(line, "public_key=")
		case strings.HasPrefix(line, "endpoint=") && cur == pubHex:
			return strings.TrimPrefix(line, "endpoint=")
		}
	}
	return ""
}

// Close는 wg를 멈추고 TUN 인터페이스를 닫는다.
func (d *Device) Close() {
	if d.dev != nil {
		d.dev.Close()
	}
}

// configureLink는 인터페이스에 터널 IP를 붙이고 터널 대역으로 가는 경로를 넣는다.
func configureLink(name, tunnelIP, cidr string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("인터페이스를 찾지 못했다: %s", name)
	}
	addr, err := netlink.ParseAddr(tunnelIP + "/32")
	if err != nil {
		return fmt.Errorf("터널 IP를 읽을 수 없다: %s", tunnelIP)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("터널 IP를 붙이지 못했다: %w", err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("MTU를 걸지 못했다: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("인터페이스를 올리지 못했다: %w", err)
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("tunnel-cidr를 읽을 수 없다: %s", cidr)
	}
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("경로를 넣지 못했다: %w", err)
	}
	return nil
}

func readKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("개인키 파일을 읽지 못했다: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
