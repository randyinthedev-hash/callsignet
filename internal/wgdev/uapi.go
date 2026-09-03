// Package wgdev는 TUN 인터페이스를 만들고 그 위에서 wg를 돌린다.
package wgdev

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/randyinthedev-hash/callsignet/internal/config"
)

// KeepaliveSeconds는 keepalive를 보내는 주기다. 상태를 기억하는 방화벽이 UDP
// 흐름을 30초에 지우는 경우가 흔하므로 그보다 짧게 잡는다.
const KeepaliveSeconds = 25

// UAPIConfig는 wireguard-go가 읽는 설정 문자열을 만든다. 키는 base64가 아니라
// 16진수로 적어야 한다.
func UAPIConfig(c *config.Config, privateKeyB64 string) (string, error) {
	priv, err := keyToHex(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("개인키를 읽을 수 없다: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	fmt.Fprintf(&b, "listen_port=%d\n", c.Self.ListenPort)
	b.WriteString("replace_peers=true\n")

	for _, peer := range c.Peers {
		if peer.PeerID == c.Self.PeerID {
			continue // 자기 자신은 상대가 아니다
		}
		pub, err := keyToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("공개키를 읽을 수 없다: %s의 %s", peer.PeerID, peer.PublicKey)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pub)
		b.WriteString("replace_allowed_ips=true\n")
		// 허용 IP는 그 상대에게 배정된 터널 IP 하나뿐이다. 이 값이 받는 쪽에서
		// 상대를 확정하는 근거가 된다.
		fmt.Fprintf(&b, "allowed_ip=%s/32\n", peer.TunnelIP)
		if len(peer.Endpoints) > 0 {
			fmt.Fprintf(&b, "endpoint=%s\n", peer.Endpoints[0])
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", KeepaliveSeconds)
	}
	return b.String(), nil
}

func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("키 길이가 32바이트가 아니다: %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// UAPIReload는 도는 wg에 걸 차이만 만든다. 바뀌지 않은 상대는 한 줄도 내지
// 않는다.
//
// 바뀌지 않은 상대를 다시 거는 것을 피하는 까닭이 있다. 접속 주소를 다시 걸면
// wg가 들고 있던 관측한 주소를 peers.toml에 적힌 값으로 되돌린다. 상대가 다른
// 자리로 옮겨 갔으면 그 자리를 잃는다.
//
// 공개키가 바뀐 상대는 wg에게 다른 상대다. 옛 키를 지우고 새 키를 넣는다.
func UAPIReload(old, cur *config.Config) (string, error) {
	oldByID := peersByID(old)
	curByID := peersByID(cur)

	var remove, add strings.Builder
	for id, p := range oldByID {
		if _, ok := curByID[id]; ok {
			continue
		}
		// 도는 설정에서 왔으므로 키는 이미 한 번 읽힌 것이다.
		if pub, err := keyToHex(p.PublicKey); err == nil {
			fmt.Fprintf(&remove, "public_key=%s\nremove=true\n", pub)
		}
	}

	ids := make([]string, 0, len(curByID))
	for id := range curByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		p := curByID[id]
		o, had := oldByID[id]
		if had && o.PublicKey == p.PublicKey && o.TunnelIP == p.TunnelIP &&
			sameEndpoint(o.Endpoints, p.Endpoints) {
			continue
		}
		pub, err := keyToHex(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("공개키를 읽을 수 없다: %s의 %s", id, p.PublicKey)
		}
		if had && o.PublicKey != p.PublicKey {
			if oldPub, err := keyToHex(o.PublicKey); err == nil {
				fmt.Fprintf(&remove, "public_key=%s\nremove=true\n", oldPub)
			}
		}
		fmt.Fprintf(&add, "public_key=%s\n", pub)
		add.WriteString("replace_allowed_ips=true\n")
		fmt.Fprintf(&add, "allowed_ip=%s/32\n", p.TunnelIP)
		if len(p.Endpoints) > 0 {
			fmt.Fprintf(&add, "endpoint=%s\n", p.Endpoints[0])
		}
		fmt.Fprintf(&add, "persistent_keepalive_interval=%d\n", KeepaliveSeconds)
	}
	// 지우는 것을 먼저 낸다. 두 상대가 키를 맞바꾸는 경우에 새 키가 옛 상대에
	// 남아 있으면 wg가 받지 않는다.
	return remove.String() + add.String(), nil
}

// peersByID는 자기 자신을 뺀 상대들을 peer-id로 찾을 수 있게 모은다.
func peersByID(c *config.Config) map[string]config.Peer {
	m := make(map[string]config.Peer, len(c.Peers))
	for _, p := range c.Peers {
		if p.PeerID == c.Self.PeerID {
			continue
		}
		m[p.PeerID] = p
	}
	return m
}

// sameEndpoint는 wg에게 거는 접속 주소가 같은지 본다. wg는 첫 주소만 쓴다.
func sameEndpoint(a, b []string) bool {
	first := func(s []string) string {
		if len(s) == 0 {
			return ""
		}
		return s[0]
	}
	return first(a) == first(b)
}
