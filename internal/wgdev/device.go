//go:build linux

package wgdev

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/randyinthedev-hash/callsignet/internal/config"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Device는 csa가 만든 TUN 인터페이스와 그 위에서 도는 wg다.
type Device struct {
	Name string
	tun  tun.Device
	dev  *device.Device
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

	t, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("TUN 인터페이스를 만들지 못했다: %w", err)
	}
	real, err := t.Name()
	if err != nil {
		t.Close()
		return nil, err
	}

	// CSA_DEBUG를 켜면 wg가 handshake와 세션을 어떻게 다루는지 모두 적는다.
	verbose := func(f string, a ...any) {}
	if os.Getenv("CSA_DEBUG") != "" {
		verbose = func(f string, a ...any) { logf("wg: "+f, a...) }
	}
	d := device.NewDevice(t, conn.NewDefaultBind(), &device.Logger{
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
	return &Device{Name: real, tun: t, dev: d}, nil
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
