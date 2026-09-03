package wgdev

import (
	"strconv"
	"strings"
	"time"
)

// PeerStatus는 wg가 그 상대 하나에 대해 알고 있는 것이다.
type PeerStatus struct {
	PublicKey string // 16진수
	Endpoint  string // 그 상대에게서 패킷이 실제로 온 주소
	Handshake time.Time
	RxBytes   int64
	TxBytes   int64
}

// parseStatus는 wg가 내놓은 상태 문자열을 공개키별로 나눈다.
//
// wg는 상대 하나마다 public_key= 줄을 먼저 내고 그 상대의 값을 그 뒤에 잇는다.
// 그래서 public_key= 줄을 만날 때마다 다음 상대로 넘어간다. 첫 public_key=
// 줄보다 앞에 있는 값은 인터페이스 자신의 것이므로 버린다.
func parseStatus(state string) map[string]PeerStatus {
	out := map[string]PeerStatus{}
	var cur string
	var sec, nsec int64

	// 상대 하나가 끝날 때 handshake 시각을 합쳐 넣는다. wg가 초와 나노초를 두
	// 줄로 나눠 내기 때문에 줄마다 바로 넣을 수 없다.
	flush := func() {
		if cur == "" {
			return
		}
		if sec > 0 {
			p := out[cur]
			p.Handshake = time.Unix(sec, nsec)
			out[cur] = p
		}
		sec, nsec = 0, 0
	}

	for _, line := range strings.Split(state, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			flush()
			cur = v
			out[cur] = PeerStatus{PublicKey: v}
			continue
		}
		if cur == "" {
			continue
		}
		p := out[cur]
		switch k {
		case "endpoint":
			p.Endpoint = v
		case "rx_bytes":
			p.RxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			p.TxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
		out[cur] = p
	}
	flush()
	return out
}
