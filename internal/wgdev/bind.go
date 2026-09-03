//go:build linux

package wgdev

import (
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// bind는 wg가 쓰는 UDP 소켓을 감싼다.
//
// 여기는 바깥 UDP 헤더의 출발지를 볼 수 있는 유일한 자리다. 다만 아직 복호화
// 전이라 어느 상대의 패킷인지는 알 수 없다. 그 짝은 wg가 복호화하면서 맞추고
// 결과를 상대의 접속 주소로 들고 있으므로, 연결 단위 관측은 그 값을 읽어 쓴다.
//
// 이 자리가 따로 하는 일은 낯선 곳을 알아채는 것이다. wg는 인증을 통과한
// 패킷만 보지만 여기는 통과하지 못한 것도 본다. 등록된 상대의 접속 주소가
// 아닌 곳에서 패킷이 오면 그것을 적는다.
type bind struct {
	conn.Bind
	logf func(string, ...any)

	mu    sync.Mutex
	known map[string]bool // 등록된 상대의 접속 주소
	odd   map[string]int  // 낯선 곳과 그곳에서 온 횟수
}

func newBind(known map[string]bool, logf func(string, ...any)) *bind {
	return &bind{
		Bind:  conn.NewDefaultBind(),
		logf:  logf,
		known: known,
		odd:   map[string]int{},
	}
}

func (b *bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.wrap(fn)
	}
	return wrapped, actual, nil
}

func (b *bind) wrap(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		for i := 0; i < n; i++ {
			if eps[i] != nil {
				b.note(eps[i].DstToString())
			}
		}
		return n, err
	}
}

// note는 낯선 곳에서 온 것을 적는다. 처음 열 번은 모두 적고 그다음부터는
// 백 번마다 적는다. 쏟아져 들어와도 로그가 묻히지 않게 하려는 것이다.
func (b *bind) note(from string) {
	if b.known[from] {
		return
	}
	b.mu.Lock()
	b.odd[from]++
	n := b.odd[from]
	b.mu.Unlock()
	if n <= 10 || n%100 == 0 {
		b.logf("등록된 접속 주소가 아닌 곳에서 패킷이 왔습니다. 출발지 %s, %d번째", from, n)
	}
}

// Odd는 낯선 곳과 그곳에서 온 횟수를 돌려준다.
func (b *bind) Odd() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]int, len(b.odd))
	for k, v := range b.odd {
		out[k] = v
	}
	return out
}
