//go:build linux

package wgdev

import "testing"

func newTestBind(known ...string) (*bind, *[]string) {
	var lines []string
	m := map[string]bool{}
	for _, k := range known {
		m[k] = true
	}
	b := &bind{
		known: m,
		odd:   map[string]int{},
		logf:  func(f string, a ...any) { lines = append(lines, f) },
	}
	return b, &lines
}

func TestBindIgnoresKnownEndpoints(t *testing.T) {
	b, lines := newTestBind("10.0.5.2:51820")
	for i := 0; i < 5; i++ {
		b.note("10.0.5.2:51820")
	}
	if len(*lines) != 0 {
		t.Fatalf("등록된 곳은 적으면 안 되는데 %d줄", len(*lines))
	}
	if len(b.Odd()) != 0 {
		t.Fatal("등록된 곳을 낯선 곳으로 세었다")
	}
}

func TestBindNotesUnknownEndpoint(t *testing.T) {
	b, lines := newTestBind("10.0.5.2:51820")
	b.note("10.0.9.9:40000")
	if len(*lines) != 1 {
		t.Fatalf("한 줄 적어야 하는데 %d줄", len(*lines))
	}
	if b.Odd()["10.0.9.9:40000"] != 1 {
		t.Fatal("낯선 곳을 세지 않았다")
	}
}

// 쏟아져 들어와도 로그가 묻히지 않아야 한다.
func TestBindThinsRepeatedNotes(t *testing.T) {
	b, lines := newTestBind()
	for i := 0; i < 250; i++ {
		b.note("10.0.9.9:40000")
	}
	// 처음 열 번과 100번째와 200번째다.
	if want := 12; len(*lines) != want {
		t.Fatalf("%d줄이어야 하는데 %d줄", want, len(*lines))
	}
	if b.Odd()["10.0.9.9:40000"] != 250 {
		t.Fatal("횟수를 잘못 세었다")
	}
}
