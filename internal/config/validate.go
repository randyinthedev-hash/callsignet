package config

import (
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
	return p
}

func (c *Config) checkSelf() []string {
	var p []string
	s := c.Self
	if s.PeerID == "" {
		p = append(p, "csa.toml에 peer-id가 없다")
	}
	if s.Domain == "" {
		p = append(p, "csa.toml에 domain이 없다")
	}
	if s.PrivateKey == "" {
		p = append(p, "csa.toml에 private-key가 없다")
	} else if _, err := os.Stat(s.PrivateKey); err != nil {
		p = append(p, fmt.Sprintf("개인키 파일을 열 수 없다: %s", s.PrivateKey))
	}
	if s.ListenPort <= 0 || s.ListenPort > 65535 {
		p = append(p, fmt.Sprintf("listen-port가 범위를 벗어났다: %d", s.ListenPort))
	}
	if s.Tun.MTU != 0 && (s.Tun.MTU < 1280 || s.Tun.MTU > 1500) {
		p = append(p, fmt.Sprintf("tun.mtu가 범위를 벗어났다: %d", s.Tun.MTU))
	}

	cidr, err := netip.ParsePrefix(s.TunnelCIDR)
	if err != nil {
		p = append(p, fmt.Sprintf("tunnel-cidr를 읽을 수 없다: %s", s.TunnelCIDR))
		return p
	}
	// 이 머신이 이미 쓰는 대역과 겹치면 원래 가던 트래픽이 터널로 들어간다.
	for _, local := range localPrefixes() {
		if cidr.Overlaps(local) {
			p = append(p, fmt.Sprintf("tunnel-cidr가 이 머신이 이미 쓰는 대역과 겹친다: %s, %s", cidr, local))
		}
	}
	return p
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
		if seenID[peer.PeerID] {
			p = append(p, fmt.Sprintf("peer-id가 두 번 나온다: %s", peer.PeerID))
		}
		seenID[peer.PeerID] = true

		if peer.PublicKey == "" {
			p = append(p, fmt.Sprintf("%s에 public-key가 없다", peer.PeerID))
		} else if other, dup := seenKey[peer.PublicKey]; dup {
			p = append(p, fmt.Sprintf("같은 공개키가 두 peer에 나타난다: %s, %s", other, peer.PeerID))
		} else {
			seenKey[peer.PublicKey] = peer.PeerID
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
			if cidrOK == nil && !cidr.Contains(ip) {
				p = append(p, fmt.Sprintf("터널 IP가 tunnel-cidr 밖이다: %s의 %s (cidr %s)", peer.PeerID, ip, cidr))
			}
		}

		for _, ep := range peer.Endpoints {
			if _, err := netip.ParseAddrPort(ep); err != nil {
				p = append(p, fmt.Sprintf("endpoint를 읽을 수 없다: %s의 %s", peer.PeerID, ep))
			}
		}
		seenApp := map[string]bool{}
		for _, svc := range peer.Services {
			if svc.App == "" {
				p = append(p, fmt.Sprintf("%s에 이름 없는 service가 있다", peer.PeerID))
			}
			if seenApp[svc.App] {
				p = append(p, fmt.Sprintf("app이 두 번 나온다: %s의 %s", peer.PeerID, svc.App))
			}
			seenApp[svc.App] = true
			if svc.Port <= 0 || svc.Port > 65535 {
				p = append(p, fmt.Sprintf("port가 범위를 벗어났다: %s/%s의 %d", peer.PeerID, svc.App, svc.Port))
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
				t, err := time.Parse("2006-01-02", in.Expires)
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

func hasApp(svcs []Service, app string) bool {
	for _, s := range svcs {
		if s.App == app {
			return true
		}
	}
	return false
}

// localPrefixes는 이 머신의 인터페이스에 붙은 대역을 돌려준다.
func localPrefixes() []netip.Prefix {
	var out []netip.Prefix
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
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
	return out
}
