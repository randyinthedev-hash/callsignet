// Package nft는 nftables 표를 거는 두 패키지가 함께 쓰는 것을 담는다.
//
// csa는 nftables 표를 둘 만든다. 직통 경로를 닫는 표(guard)와 실제 IP와 터널
// IP를 서로 바꾸는 표(nat)다. 둘은 같은 nft 명령을 같은 자리에서 찾고, 계수기를
// 같은 모양으로 읽는다. 그 자리를 한 곳에 둔다.
package nft

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// Find는 nft 명령을 찾는다. PATH에서 먼저 찾고, 없으면 sbin 자리들을 본다.
// RHEL 계열은 서비스나 SSH로 바로 띄운 명령의 PATH에 /usr/sbin을 넣지 않는다.
// csa가 어디서 뜨든 같은 자리를 보아야 한다.
func Find() (string, error) {
	if p, err := exec.LookPath("nft"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/local/sbin/nft"} {
		if st, err := os.Stat(p); err == nil && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("nft를 찾지 못했다. nftables를 설치하거나" +
		" csa.toml에 guard.mode = \"off\"와 nat.outgoing = \"off\", nat.incoming = \"tunnel-ip\"를 두라")
}

// Look은 nft를 찾는다. 시험이 갈아 끼울 수 있게 변수로 둔다. 시험 머신에
// /usr/sbin/nft가 있으면 「찾지 못한 자리」를 다른 방법으로 만들 수 없다.
var Look = Find

// Count는 nft -j list counter가 내놓은 JSON에서 계수기가 센 패킷 수를 뽑는다.
func Count(b []byte) uint64 {
	var doc struct {
		Nftables []struct {
			Counter struct {
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return 0
	}
	for _, item := range doc.Nftables {
		if item.Counter.Packets > 0 {
			return item.Counter.Packets
		}
	}
	return 0
}
