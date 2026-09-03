package control

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Status는 csa status가 보여 주는 값이다. 도는 csa가 JSON으로 내고 csa status가
// 읽어 표로 찍는다.
type Status struct {
	PeerID   string       `json:"peer-id"`
	Iface    string       `json:"iface"`
	TunnelIP string       `json:"tunnel-ip"`
	Domain   string       `json:"domain"`
	Resolver string       `json:"resolver"`
	Since    time.Time    `json:"since"`
	Peers    []PeerStatus `json:"peers"`
}

// PeerStatus는 상대 하나의 상태다. Handshake가 비어 있으면 아직 한 번도 세션을
// 맺지 않은 것이다.
type PeerStatus struct {
	PeerID    string    `json:"peer-id"`
	TunnelIP  string    `json:"tunnel-ip"`
	Endpoint  string    `json:"endpoint"`
	Handshake time.Time `json:"handshake"`
	RxBytes   int64     `json:"rx-bytes"`
	TxBytes   int64     `json:"tx-bytes"`
}

// Format은 상태를 사람이 읽을 표로 만든다. now를 받는 것은 시험이 시각을
// 고정할 수 있게 하려는 것이다.
func Format(s Status, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "csa %s가 돕니다. 기동한 지 %s 지났습니다.\n", s.PeerID, span(now.Sub(s.Since)))
	fmt.Fprintf(&b, "인터페이스 %s, 터널 IP %s, 도메인 %s\n", s.Iface, s.TunnelIP, s.Domain)
	fmt.Fprintf(&b, "이름 해석 관리 주체는 %s입니다.\n\n", s.Resolver)

	if len(s.Peers) == 0 {
		b.WriteString("peers.toml에 다른 상대가 없습니다.\n")
		return b.String()
	}

	peers := append([]PeerStatus(nil), s.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].PeerID < peers[j].PeerID })

	rows := [][]string{{"peer", "터널 IP", "관측한 출발지", "마지막 handshake", "받음", "보냄"}}
	for _, p := range peers {
		rows = append(rows, []string{
			p.PeerID, p.TunnelIP, dash(p.Endpoint), when(p.Handshake, now),
			size(p.RxBytes), size(p.TxBytes),
		})
	}
	b.WriteString(table(rows))
	return b.String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// when은 handshake 시각을 얼마나 지났는지로 바꾼다.
func when(t, now time.Time) string {
	if t.IsZero() {
		return "없음"
	}
	return span(now.Sub(t)) + " 전"
}

// span은 시간 길이를 한국어로 적는다.
func span(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d초", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d분 %d초", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%d시간 %d분", int(d.Hours()), int(d.Minutes())%60)
	}
}

// size는 바이트 수를 사람이 읽을 단위로 바꾼다.
func size(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// table은 열을 맞춰 찍는다. 열 너비는 화면에서 차지하는 칸 수로 잰다.
func table(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	w := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, cell := range r {
			if n := width(cell); n > w[i] {
				w[i] = n
			}
		}
	}
	var b strings.Builder
	for _, r := range rows {
		for i, cell := range r {
			b.WriteString(cell)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", w[i]-width(cell)+2))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// width는 그 문자열이 화면에서 차지하는 칸 수다. 한글과 한자는 두 칸이다.
func width(s string) int {
	n := 0
	for _, r := range s {
		if wide(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func wide(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // 한글 자모
		r >= 0x2E80 && r <= 0xA4CF, // 한자와 부수
		r >= 0xAC00 && r <= 0xD7A3, // 한글 음절
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60, // 전각
		r >= 0xFFE0 && r <= 0xFFE6:
		return true
	}
	return false
}
