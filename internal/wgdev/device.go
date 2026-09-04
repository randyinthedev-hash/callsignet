//go:build linux

package wgdev

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/randyinthedev-hash/callsignet/internal/config"
	"github.com/randyinthedev-hash/callsignet/internal/policy"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Device는 csa가 만든 TUN 인터페이스와 그 위에서 도는 wg다.
type Device struct {
	Name string
	flt  *filter
	bnd  *bind
	dev  *device.Device
	// snap은 설정에서 뽑아 둔 값들이다. csa reload가 통째로 갈아 끼운다.
	snap atomic.Pointer[snapshot]
	// eps는 wg에게 물어 얻은 상대별 접속 주소를 잠깐 들고 있는 자리다.
	eps endpoints
}

// endpointTTL은 wg에게 접속 주소를 다시 묻기까지 기다리는 시간이다.
//
// 묻는 것이 값싸지 않다. wg가 IpcGet에서 상태 전체를 문자열로 만들어 내놓기
// 때문이다. IP 대역 규칙은 패킷마다 이 값을 보므로 그때마다 물을 수 없다.
//
// 여기서 오는 결과가 하나 있다. 상대가 다른 자리로 옮겨 가면 IP 대역 규칙이
// 그것을 이 시간만큼 늦게 안다. 대역은 상대를 확정하는 근거가 아니라 그 위에
// 더한 조건이므로, 이만큼의 늦음을 받아들인다.
const endpointTTL = time.Second

type endpoints struct {
	mu   sync.Mutex
	at   time.Time
	byID map[string]string
}

// snapshot은 설정에서 미리 뽑아 둔 것이다. 패킷마다 설정을 훑지 않으려고 둔다.
type snapshot struct {
	cfg *config.Config
	// pubOf는 peer-id로 그 상대의 공개키를 찾는다. wg에게 접속 주소를 물을 때 쓴다.
	pubOf map[string]string
	// known은 등록된 상대의 접속 주소다. 낯선 곳을 가릴 때 쓴다.
	known map[string]bool
}

func newSnapshot(c *config.Config) *snapshot {
	s := &snapshot{cfg: c, pubOf: map[string]string{}, known: map[string]bool{}}
	for _, peer := range c.Peers {
		if peer.PeerID == c.Self.PeerID {
			continue
		}
		if hexKey, err := keyToHex(peer.PublicKey); err == nil {
			s.pubOf[peer.PeerID] = hexKey
		}
		for _, ep := range peer.Endpoints {
			s.known[ep] = true
		}
	}
	return s
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

	mtu := c.Self.TunMTU()
	name := c.Self.TunName()

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
	out := &Device{Name: real}
	snap := newSnapshot(c)
	out.snap.Store(snap)
	t := &filter{
		Device: raw, logf: logf, observe: out.endpointOf,
		flows: newFlows(logTTL, logMax), conns: newFlows(connTTL, connMax),
		// IP 헤더 20바이트와 TCP 헤더 20바이트를 뺀 것이 세그먼트에 쓸 수 있는 크기다.
		maxMSS: uint16(mtu - 40),
	}
	t.rules.Store(rules)
	b := newBind(snap.known, logf)

	// CSA_DEBUG를 켜면 wg가 handshake와 세션을 어떻게 다루는지 모두 적는다.
	verbose := func(f string, a ...any) {}
	if os.Getenv("CSA_DEBUG") != "" {
		verbose = func(f string, a ...any) { logf("wg: "+f, a...) }
	}
	d := device.NewDevice(t, b, &device.Logger{
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
	checkUnderlayMTU(c, mtu, logf)
	out.flt, out.bnd, out.dev = t, b, d
	return out, nil
}

// wgOverheadV4는 wg가 원래 IPv4 패킷에 덧붙이는 크기다. 바깥 IP 헤더 20바이트,
// UDP 헤더 8바이트, wg 자신의 헤더와 인증 꼬리표 32바이트를 더한 값이다.
const wgOverheadV4 = 60

// checkUnderlayMTU는 터널 MTU가 바깥 인터페이스의 MTU 안에 들어가는지 보고
// 운영자에게 알린다.
//
// 들어가지 않으면 큰 패킷이 조각나거나 조용히 사라진다. 작은 요청은 오가는데 큰
// 응답에서 멈추는 증상으로 나타나 원인을 찾기 어렵다. 그래서 csa가 기동할 때
// 스스로 견주어 적어 둔다. 막지는 않는다. 조직이 알고 그렇게 두는 경우가 있다.
func checkUnderlayMTU(c *config.Config, mtu int, logf func(string, ...any)) {
	seen := map[int]bool{}
	for _, peer := range c.Peers {
		if peer.PeerID == c.Self.PeerID {
			continue
		}
		for _, ep := range peer.Endpoints {
			ap, err := netip.ParseAddrPort(ep)
			if err != nil {
				continue
			}
			routes, err := netlink.RouteGet(net.IP(ap.Addr().AsSlice()))
			if err != nil || len(routes) == 0 {
				continue
			}
			link, err := netlink.LinkByIndex(routes[0].LinkIndex)
			if err != nil || seen[routes[0].LinkIndex] {
				continue
			}
			seen[routes[0].LinkIndex] = true

			outer := link.Attrs().MTU
			if mtu+wgOverheadV4 > outer {
				logf("터널 MTU가 너무 큽니다. 바깥 인터페이스 %s의 MTU %d, 터널 MTU %d,"+
					" wg가 덧붙이는 크기 %d바이트입니다. csa.toml의 tun.mtu를 이 값 이하로 낮추십시오: %d",
					link.Attrs().Name, outer, mtu, wgOverheadV4, outer-wgOverheadV4)
			} else {
				logf("터널 MTU를 확인했습니다. 바깥 인터페이스 %s의 MTU %d, 터널 MTU %d,"+
					" wg가 덧붙이는 크기 %d바이트입니다.",
					link.Attrs().Name, outer, mtu, wgOverheadV4)
			}
		}
	}
}

// Reload는 새 설정을 도는 csa에 건다.
//
// wg에는 바뀐 상대만 건다. 정책과 이름에 쓰는 값은 통째로 갈아 끼운다. 규칙을
// 먼저 만들어 두고 wg를 건드리는 까닭은, 규칙을 만들다 실패하면 아무것도 바꾸지
// 않은 채로 돌아가게 하려는 것이다.
func (d *Device) Reload(c *config.Config) error {
	uapi, err := UAPIReload(d.snap.Load().cfg, c)
	if err != nil {
		return err
	}
	rules, err := policy.New(c)
	if err != nil {
		return err
	}
	if uapi != "" {
		if err := d.dev.IpcSet(uapi); err != nil {
			return fmt.Errorf("wg 설정을 다시 걸지 못했다: %w", err)
		}
	}
	snap := newSnapshot(c)
	d.flt.rules.Store(rules)
	d.bnd.setKnown(snap.known)
	d.snap.Store(snap)
	return nil
}

// endpointOf는 그 상대에게서 패킷이 실제로 온 주소를 돌려준다. wg가 복호화하면서
// 짝을 맞춰 둔 값이다. 인증을 통과한 패킷일 때만 갱신되므로 아무나 이 값을 바꿀
// 수 없다. endpointTTL 동안은 앞서 물어 둔 값을 그대로 쓴다.
func (d *Device) endpointOf(peerID string) string {
	d.eps.mu.Lock()
	defer d.eps.mu.Unlock()
	if now := time.Now(); now.Sub(d.eps.at) > endpointTTL {
		d.eps.byID = d.readEndpoints()
		d.eps.at = now
	}
	return d.eps.byID[peerID]
}

// readEndpoints는 wg에게 모든 상대의 접속 주소를 한 번에 묻는다.
func (d *Device) readEndpoints() map[string]string {
	out := map[string]string{}
	if d.dev == nil {
		return out
	}
	state, err := d.dev.IpcGet()
	if err != nil {
		return out
	}
	byKey := parseStatus(state)
	for peerID, pub := range d.snap.Load().pubOf {
		if p, ok := byKey[pub]; ok && p.Endpoint != "" {
			out[peerID] = p.Endpoint
		}
	}
	return out
}

// endpointFor는 wg가 내놓은 상태에서 그 공개키의 접속 주소를 찾는다.
func endpointFor(state, pubHex string) string {
	return parseStatus(state)[pubHex].Endpoint
}

// Status는 wg에게 상대들의 상태를 물어 peer-id를 붙여 돌려준다. csa status가 쓴다.
func (d *Device) Status() map[string]PeerStatus {
	out := map[string]PeerStatus{}
	if d.dev == nil {
		return out
	}
	state, err := d.dev.IpcGet()
	if err != nil {
		return out
	}
	byKey := parseStatus(state)
	for peerID, pub := range d.snap.Load().pubOf {
		if p, ok := byKey[pub]; ok {
			out[peerID] = p
		}
	}
	return out
}

// MaxMSS는 이 터널이 나를 수 있는 TCP 세그먼트 크기다.
func (d *Device) MaxMSS() uint16 { return d.flt.maxMSS }

// MSSClamped는 지금까지 TCP 최대 세그먼트 크기를 깎은 횟수다.
func (d *Device) MSSClamped() uint64 { return d.flt.clamped.Load() }

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
