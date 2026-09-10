package config

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Validate는 설정이 어긋난 곳을 모두 찾아 돌려준다. 하나를 찾고 멈추지 않는다.
// 운영자가 한 번에 고칠 수 있게 하려는 것이다.
func (c *Config) Validate() []string {
	var p []string
	p = append(p, c.checkSelf()...)
	p = append(p, c.checkPeers()...)
	p = append(p, c.checkPolicy()...)
	p = append(p, c.checkKeyPair()...)
	p = append(p, c.checkPSK()...)
	return p
}

func (c *Config) checkSelf() []string {
	var p []string
	s := c.Self
	if s.PeerID == "" {
		p = append(p, "csa.toml에 peer-id가 없다")
	} else if msg := checkLabel("peer-id", s.PeerID); msg != "" {
		p = append(p, msg)
	}
	if msg := checkDomain(s.Domain); msg != "" {
		p = append(p, msg)
	}
	if s.PrivateKey == "" {
		p = append(p, "csa.toml에 private-key가 없다")
	} else if msg := checkSecretFile("개인키", s.PrivateKey); msg != "" {
		p = append(p, msg)
	}
	if s.ListenPort <= 0 || s.ListenPort > 65535 {
		p = append(p, fmt.Sprintf("listen-port가 범위를 벗어났다: %d", s.ListenPort))
	}
	if s.DNS.Listen == "" {
		p = append(p, "csa.toml에 dns.listen이 없다")
	} else if ap, err := netip.ParseAddrPort(s.DNS.Listen); err != nil {
		p = append(p, fmt.Sprintf("dns.listen을 읽을 수 없다: %s", s.DNS.Listen))
	} else {
		// resolv.conf의 nameserver 줄에는 포트를 적을 수 없다. 53이 아니면
		// 리졸버가 csa에 묻지 못한다.
		if ap.Port() != 53 {
			p = append(p, fmt.Sprintf("dns.listen의 포트는 53이어야 한다: %s", s.DNS.Listen))
		}
		// 이 이름 해석기는 이 머신 안에서만 쓴다. 밖으로 열면 조직의 내부
		// 이름을 아무나 물어볼 수 있다.
		if !ap.Addr().IsLoopback() {
			p = append(p, fmt.Sprintf("dns.listen은 루프백 주소여야 한다: %s", s.DNS.Listen))
		}
	}
	if s.ListenPort == 53 {
		p = append(p, "listen-port를 53으로 둘 수 없다. csa가 그 포트에서 이름 해석을 받는다")
	}
	if msg := checkIface(s.TunName()); msg != "" {
		p = append(p, msg)
	}
	if s.Tun.MTU != 0 && (s.Tun.MTU < 1280 || s.Tun.MTU > 1500) {
		p = append(p, fmt.Sprintf("tun.mtu가 범위를 벗어났다: %d", s.Tun.MTU))
	}
	p = append(p, checkGuard(s.Guard)...)

	cidr, err := netip.ParsePrefix(s.TunnelCIDR)
	if err != nil {
		p = append(p, fmt.Sprintf("tunnel-cidr를 읽을 수 없다: %s", s.TunnelCIDR))
		return p
	}
	// csa는 터널 인터페이스에 IPv4 주소를 붙이고 경로도 IPv4로 넣는다. IPv6
	// 패킷은 읽지 않고 버린다. 상대의 접속 주소는 IPv6도 된다. 그것은 wg가
	// 바깥에서 쓰는 주소이고 터널 안의 주소가 아니다.
	if !cidr.Addr().Is4() {
		p = append(p, fmt.Sprintf("tunnel-cidr는 IPv4여야 한다: %s", s.TunnelCIDR))
		return p
	}
	// csa는 이 대역으로 역방향 구역을 만들어 이름 해석기에 등록한다. 8비트
	// 단위가 아니면 구역 이름을 만들 수 없어 기동하지 못한다.
	if b := cidr.Bits(); b == 0 || b%8 != 0 {
		p = append(p, fmt.Sprintf("tunnel-cidr는 /8, /16, /24처럼 8비트 단위여야 한다: %s", s.TunnelCIDR))
	}
	// 이 머신이 이미 쓰는 대역과 겹치면 원래 가던 트래픽이 터널로 들어간다.
	for _, local := range localPrefixes(s.TunName()) {
		if cidr.Overlaps(local) {
			p = append(p, fmt.Sprintf("tunnel-cidr가 이 머신이 이미 쓰는 대역과 겹친다: %s, %s", cidr, local))
		}
	}
	return p
}

func checkGuard(g Guard) []string {
	var p []string
	switch g.Mode {
	case "", "services", "all", "off":
	default:
		p = append(p, fmt.Sprintf("guard.mode는 services, all, off 가운데 하나여야 한다: %s", g.Mode))
	}
	for _, port := range append(append([]int{}, g.KeepTCP...), g.KeepUDP...) {
		if port <= 0 || port > 65535 {
			p = append(p, fmt.Sprintf("guard의 열어 둘 포트가 범위를 벗어났다: %d", port))
		}
	}
	// 적어 두고 안 쓰이면 운영자가 열었다고 잘못 안다.
	if g.Mode != "all" && (len(g.KeepTCP) > 0 || len(g.KeepUDP) > 0) {
		p = append(p, "guard.keep-tcp와 guard.keep-udp는 guard.mode가 all일 때만 쓴다")
	}
	return p
}

// publicKey는 적어 둔 공개키를 읽어 다듬은 모양으로 돌려준다. csa가 wg에 설정을
// 넣을 때 같은 것을 하는데, 그때 실패하면 이미 기동한 뒤라 운영자가 까닭을 찾기
// 어렵다. 그래서 설정 검사에서 먼저 본다.
// checkSecretFile은 비밀을 담은 파일이 안전한 자리에 있는지 본다.
//
// 있는지만 보아서는 모자란다. 디렉터리도 Stat을 지나고, 읽을 수 없는 파일도
// 지난다. 무엇보다 0644인 개인키가 그대로 지나면 다른 사용자가 그 머신의
// 신원을 가져갈 수 있다. csa가 만든 파일은 0600이지만 운영자가 다른 곳에서
// 옮겨 온 파일은 그렇지 않다.
func checkSecretFile(kind, path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("%s 파일을 열 수 없다: %s", kind, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Sprintf("%s 자리가 일반 파일이 아니다: %s", kind, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("%s 파일을 다른 사용자가 읽을 수 있다. 0600으로 두라: %s (지금 %o)",
			kind, path, perm)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("%s 파일을 읽을 수 없다: %s", kind, path)
	}
	f.Close()
	return ""
}

// checkIface는 리눅스가 받아들이는 인터페이스 이름인지 본다.
//
// 커널이 이름을 15글자까지 받고 슬래시와 공백을 받지 않는다. 넘거나 어긋나면
// csa가 인터페이스를 만들지 못해 기동에서 실패한다. 설정 검사에서 먼저 잡는다.
func checkIface(v string) string {
	if v == "" {
		return "tun.name이 비어 있다"
	}
	if len(v) > 15 {
		return "tun.name이 15글자를 넘는다: " + v
	}
	if v == "." || v == ".." {
		return "tun.name으로 쓸 수 없다: " + v
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '/' || c == ':' || c <= ' ' || c == 0x7f {
			return "tun.name에 쓸 수 없는 글자가 있다: " + v
		}
	}
	return ""
}

// checkLabel은 DNS 이름의 한 조각으로 쓸 수 있는지 본다.
//
// peer-id와 app은 이름 해석기의 표에 들어가고, 표는 이름을 소문자로 바꾼다.
// 그대로 두면 Srv-A와 srv-a가 설정 검사를 지나 표에서 부딪힌다. peer-id는
// 제어 소켓의 경로와 사전 공유키 파일의 이름에도 그대로 들어가므로 /와 ..
// 같은 글자도 막아야 한다. DNS 조각의 규칙이 그 둘을 함께 막는다.
func checkLabel(kind, v string) string {
	if v == "" {
		return kind + "가 비어 있다"
	}
	if len(v) > 63 {
		return fmt.Sprintf("%s가 63글자를 넘는다: %s", kind, v)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Sprintf("%s에는 소문자와 숫자와 붙임표만 쓸 수 있다: %s", kind, v)
		}
	}
	if v[0] == '-' || v[len(v)-1] == '-' {
		return fmt.Sprintf("%s는 붙임표로 시작하거나 끝날 수 없다: %s", kind, v)
	}
	return ""
}

// checkDomain은 도메인이 DNS 이름의 모양인지 본다.
func checkDomain(v string) string {
	if v == "" {
		return "csa.toml에 domain이 없다"
	}
	if len(v) > 253 {
		return "domain이 253글자를 넘는다: " + v
	}
	for _, label := range strings.Split(v, ".") {
		if msg := checkLabel("domain의 조각", label); msg != "" {
			return msg
		}
	}
	return ""
}

func publicKey(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("base64가 아니다: %s", b64)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("길이가 32바이트가 아니다: %d", len(raw))
	}
	// 전부 0인 값은 X25519의 공개키가 아니다. 그것으로는 세션이 서지 않는다.
	zero := true
	for _, b := range raw {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return "", fmt.Errorf("전부 0이다. 공개키가 아니다")
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (c *Config) checkPeers() []string {
	var p []string
	if len(c.Peers) == 0 {
		return append(p, "peers.toml에 peer가 하나도 없다")
	}
	cidr, cidrOK := netip.ParsePrefix(c.Self.TunnelCIDR)

	seenID := map[string]bool{}
	seenIP := map[string]string{}
	seenKey := map[string]string{}
	for _, peer := range c.Peers {
		if peer.PeerID == "" {
			p = append(p, "peer-id가 없는 항목이 있다")
			continue
		}
		if msg := checkLabel("peer-id", peer.PeerID); msg != "" {
			p = append(p, msg)
		}
		if seenID[peer.PeerID] {
			p = append(p, fmt.Sprintf("peer-id가 두 번 나온다: %s", peer.PeerID))
		}
		seenID[peer.PeerID] = true

		// 공개키는 읽어 낸 값으로 견준다. 앞뒤 공백처럼 적은 모양만 다른 같은
		// 키를 문자열로 견주면 서로 다른 키로 본다.
		switch key, err := publicKey(peer.PublicKey); {
		case peer.PublicKey == "":
			p = append(p, fmt.Sprintf("%s에 public-key가 없다", peer.PeerID))
		case err != nil:
			p = append(p, fmt.Sprintf("public-key를 읽을 수 없다: %s의 %v", peer.PeerID, err))
		default:
			if other, dup := seenKey[key]; dup {
				p = append(p, fmt.Sprintf("같은 공개키가 두 peer에 나타난다: %s, %s", other, peer.PeerID))
			} else {
				seenKey[key] = peer.PeerID
			}
		}

		ip, err := netip.ParseAddr(peer.TunnelIP)
		switch {
		case err != nil:
			p = append(p, fmt.Sprintf("tunnel-ip를 읽을 수 없다: %s의 %s", peer.PeerID, peer.TunnelIP))
		default:
			if other, dup := seenIP[peer.TunnelIP]; dup {
				p = append(p, fmt.Sprintf("터널 IP가 겹친다: %s (%s, %s)", peer.TunnelIP, other, peer.PeerID))
			} else {
				seenIP[peer.TunnelIP] = peer.PeerID
			}
			if !ip.Is4() {
				p = append(p, fmt.Sprintf("tunnel-ip는 IPv4여야 한다: %s의 %s", peer.PeerID, peer.TunnelIP))
			}
			if cidrOK == nil && !cidr.Contains(ip) {
				p = append(p, fmt.Sprintf("터널 IP가 tunnel-cidr 밖이다: %s의 %s (cidr %s)", peer.PeerID, ip, cidr))
			}
		}

		for _, ep := range peer.Endpoints {
			ap, err := netip.ParseAddrPort(ep)
			switch {
			case err != nil:
				p = append(p, fmt.Sprintf("endpoint를 읽을 수 없다: %s의 %s", peer.PeerID, ep))
			case ap.Port() == 0:
				// 0번 포트로는 붙을 수 없다. wg가 그 주소로 handshake를 걸지 못한다.
				p = append(p, fmt.Sprintf("endpoint의 포트가 0이다: %s의 %s", peer.PeerID, ep))
			}
		}
		seenApp := map[string]bool{}
		seenPort := map[int]string{}
		for _, svc := range peer.Services {
			if svc.App == "" {
				p = append(p, fmt.Sprintf("%s에 이름 없는 service가 있다", peer.PeerID))
			} else if msg := checkLabel("app", svc.App); msg != "" {
				p = append(p, msg)
			}
			// csa는 터널 IP의 53번 포트에서도 이름 해석을 받는다.
			if svc.Port == 53 {
				p = append(p, fmt.Sprintf("서비스 포트를 53으로 둘 수 없다: %s의 %s", peer.PeerID, svc.App))
			}
			if seenApp[svc.App] {
				p = append(p, fmt.Sprintf("app이 두 번 나온다: %s의 %s", peer.PeerID, svc.App))
			}
			seenApp[svc.App] = true
			if svc.Port <= 0 || svc.Port > 65535 {
				p = append(p, fmt.Sprintf("port가 범위를 벗어났다: %s/%s의 %d", peer.PeerID, svc.App, svc.Port))
			}
			// 집행은 포트로 한다. 한 peer 안에서 포트가 겹치면 두 앱의 정책이
			// 하나로 합쳐져, 한쪽에 준 권한이 다른 쪽까지 연다.
			if other, dup := seenPort[svc.Port]; dup {
				p = append(p, fmt.Sprintf("한 peer 안에서 포트가 겹친다: %s의 %d (%s, %s)",
					peer.PeerID, svc.Port, other, svc.App))
			} else {
				seenPort[svc.Port] = svc.App
			}
			// 서비스 포트를 wg가 듣는 포트로 두면 직통 경로를 닫을 때 터널
			// 자신이 막힌다.
			if peer.PeerID == c.Self.PeerID && svc.Port == c.Self.ListenPort {
				p = append(p, fmt.Sprintf("서비스 포트가 listen-port와 같다: %s의 %d", svc.App, svc.Port))
			}
		}
	}

	if c.Self.PeerID != "" && !seenID[c.Self.PeerID] {
		p = append(p, fmt.Sprintf("csa.toml의 peer-id가 peers.toml에 없다: %s", c.Self.PeerID))
	}
	return p
}

func (c *Config) checkPolicy() []string {
	var p []string
	self := c.Find(c.Self.PeerID)

	for _, in := range c.Policy.Inbound {
		if self != nil && !hasApp(self.Services, in.App) {
			p = append(p, fmt.Sprintf("inbound가 가리키는 app이 이 머신의 서비스에 없다: %s", in.App))
		}
		for _, id := range in.Allow {
			if c.Find(id) == nil {
				p = append(p, fmt.Sprintf("inbound의 allow가 가리키는 peer가 peers.toml에 없다: %s", id))
			}
		}
		for _, cidr := range in.AllowCIDR {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				p = append(p, fmt.Sprintf("inbound의 allow-cidr를 읽을 수 없다: %s", cidr))
			}
		}
		// IP 대역만 보는 규칙은 기본이 금지다. 켤 때 만료 기한을 함께 적는다.
		if len(in.AllowCIDR) > 0 {
			switch {
			case in.Expires == "":
				p = append(p, fmt.Sprintf("allow-cidr에 expires가 없다: app %s", in.App))
			default:
				t, err := time.ParseInLocation("2006-01-02", in.Expires, time.Local)
				if err != nil {
					p = append(p, fmt.Sprintf("expires를 읽을 수 없다: app %s의 %s", in.App, in.Expires))
				} else if t.Before(time.Now()) {
					p = append(p, fmt.Sprintf("allow-cidr가 이미 만료됐다: app %s, %s", in.App, in.Expires))
				}
			}
		}
	}

	for _, target := range c.Policy.Outbound {
		id, app, ok := strings.Cut(target, "/")
		if !ok {
			p = append(p, fmt.Sprintf("outbound는 peer-id/app 형태여야 한다: %s", target))
			continue
		}
		peer := c.Find(id)
		if peer == nil {
			p = append(p, fmt.Sprintf("outbound가 가리키는 peer가 peers.toml에 없다: %s", id))
			continue
		}
		if !hasApp(peer.Services, app) {
			p = append(p, fmt.Sprintf("peer에 app이 없다: %s의 %s", id, app))
		}
	}
	return p
}

// checkKeyPair는 개인키에서 공개키를 끌어내 peers.toml의 자기 항목과 견준다.
//
// 이 검사가 없으면 다른 검사가 모두 통과해 csa가 뜨고서도, 다른 머신이 기대하는
// 신원과 이 csa의 키가 달라 아무와도 세션을 맺지 못한다. 막히는 것이 아니라
// 통하지 않는 잘못이고, 운영자가 까닭을 찾기 매우 어렵다. 그래서 여기서 잡는다.
func (c *Config) checkKeyPair() []string {
	self := c.Find(c.Self.PeerID)
	if self == nil || c.Self.PrivateKey == "" {
		return nil // 다른 검사가 이미 잡는다
	}
	raw, err := os.ReadFile(c.Self.PrivateKey)
	if err != nil {
		return nil // 파일이 없는 것도 다른 검사가 잡는다
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(priv) != 32 {
		return []string{fmt.Sprintf("개인키 파일의 내용이 32바이트 base64가 아니다: %s", c.Self.PrivateKey)}
	}
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return []string{fmt.Sprintf("개인키를 쓸 수 없다: %s", c.Self.PrivateKey)}
	}
	got := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if got != strings.TrimSpace(self.PublicKey) {
		return []string{fmt.Sprintf("개인키와 peers.toml의 자기 공개키가 짝이 아니다."+
			" 개인키에서 나온 값 %s, peers.toml에 적힌 값 %s", got, self.PublicKey)}
	}
	return nil
}

// checkPSK는 사전 공유키 설정을 본다.
func (c *Config) checkPSK() []string {
	var p []string
	switch c.Self.PSK.Mode {
	case "", "optional", "required":
	default:
		p = append(p, fmt.Sprintf("psk.mode는 optional과 required 가운데 하나여야 한다: %s", c.Self.PSK.Mode))
	}
	if c.Self.PSK.Mode == "required" && c.Self.PSK.Dir == "" {
		return append(p, "psk.mode가 required인데 psk.dir가 없다")
	}
	if c.Self.PSK.Dir == "" {
		return p
	}
	for _, peer := range c.Peers {
		if peer.PeerID == c.Self.PeerID {
			continue
		}
		_, ok, err := c.LoadPSK(peer.PeerID)
		if err != nil {
			p = append(p, err.Error())
			continue
		}
		if !ok {
			if c.Self.PSK.Mode == "required" {
				p = append(p, fmt.Sprintf("psk.mode가 required인데 사전 공유키가 없다: %s", c.PSKPath(peer.PeerID)))
			}
			continue
		}
		// 개인키와 같은 이유로 이 파일도 다른 사용자가 읽을 수 없어야 한다.
		if msg := checkSecretFile("사전 공유키", c.PSKPath(peer.PeerID)); msg != "" {
			p = append(p, msg)
		}
	}
	return p
}

func hasApp(svcs []Service, app string) bool {
	for _, s := range svcs {
		if s.App == app {
			return true
		}
	}
	return false
}

// localPrefixes는 이 머신의 인터페이스에 붙은 대역을 모은다. skip이라는 이름의
// 인터페이스는 뺀다.
//
// csa가 만든 인터페이스를 빼는 까닭이 있다. 도는 중에 이 검사를 하면 csa가
// 스스로 붙여 둔 터널 IP가 잡혀, 자기 대역과 겹친다고 말하게 된다. csa reload가
// 그런 자리이고, 운영자가 도는 머신에서 csa check를 할 때도 그렇다.
func localPrefixes(skip string) []netip.Prefix {
	var out []netip.Prefix
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Name == skip {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			ones, _ := n.Mask.Size()
			pfx, err := ip.Unmap().Prefix(ones)
			if err != nil || pfx.Addr().IsLoopback() {
				continue
			}
			out = append(out, pfx)
		}
	}
	return out
}
