// Package wgdev는 TUN 인터페이스를 만들고 그 위에서 wg를 돌린다.
package wgdev

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
