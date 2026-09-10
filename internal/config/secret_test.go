package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// 비밀 파일을 하나 만든다.
func secretFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadSecret바른파일을읽는다(t *testing.T) {
	path := secretFile(t, "private.key", "내용\n")
	b, err := ReadSecret("개인키", path)
	if err != nil {
		t.Fatalf("바른 파일을 거절했다: %v", err)
	}
	if string(b) != "내용\n" {
		t.Fatalf("읽은 것이 다르다: %q", b)
	}
}

// TestReadSecret심볼릭링크를따르지않는다는 검사와 사용 사이에 파일을 갈아
// 끼우는 자리를 막았는지 본다.
//
// csa는 비밀 파일의 임자와 권한을 본다. 그런데 그 경로가 심볼릭 링크면 링크가
// 가리키는 곳을 다른 사용자가 바꿀 수 있다. 그러면 csa가 검사한 파일과 읽는
// 파일이 다른 것이 된다. csa는 링크를 따르지 않는다.
func TestReadSecret심볼릭링크를따르지않는다(t *testing.T) {
	path := secretFile(t, "private.key", "내용\n")
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSecret("개인키", link)
	if err == nil {
		t.Fatal("심볼릭 링크를 따라갔다")
	}
	if !strings.Contains(err.Error(), "심볼릭 링크") {
		t.Fatalf("까닭을 심볼릭 링크라고 적지 않았다: %v", err)
	}
}

// TestReadSecretFIFO에서멈추지않는다는 csa가 멈춰 서는 자리를 막았는지 본다.
//
// FIFO를 읽기로 열면 쓰는 쪽이 붙을 때까지 열기 자체가 멈춘다. 운영자가 실수로
// 또는 남이 일부러 개인키 자리에 FIFO를 두면 csa나 csa check가 그 자리에서
// 멈춘다. csa는 멈추지 않고 일반 파일이 아니라고 적고 나온다.
func TestReadSecretFIFO에서멈추지않는다(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("이 머신에서 FIFO를 만들지 못했다: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadSecret("개인키", path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO를 비밀 파일로 받아들였다")
		}
		if !strings.Contains(err.Error(), "일반 파일이 아니다") {
			t.Fatalf("까닭을 일반 파일이 아니라고 적지 않았다: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FIFO를 열다가 멈췄다")
	}
}

func TestReadSecret너무큰파일을거절한다(t *testing.T) {
	path := secretFile(t, "private.key", string(bytes.Repeat([]byte("a"), secretLimit+1)))
	if _, err := ReadSecret("개인키", path); err == nil {
		t.Fatal("한계를 넘는 파일을 받아들였다")
	}
}

// TestLoadPSK도같은검사를받는다는 사전 공유키가 개인키와 같은 길로 열리는지 본다.
//
// 앞서는 LoadPSK가 내용을 먼저 읽고 나서 파일의 종류와 권한을 보았다. 그래서
// 그 검사에 닿기 전에 FIFO에서 멈출 수 있었다.
func TestLoadPSK도같은검사를받는다(t *testing.T) {
	dir := t.TempDir()
	c := &Config{
		Self:  Self{PeerID: "srv-a", PSK: PSK{Dir: dir, Mode: "required"}},
		Peers: []Peer{{PeerID: "srv-b"}},
	}
	key := make([]byte, 32)
	key[0] = 1
	path := filepath.Join(dir, "srv-b.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.LoadPSK("srv-b")
	if err == nil {
		t.Fatal("다른 사용자가 읽을 수 있는 사전 공유키를 받아들였다")
	}
	if !strings.Contains(err.Error(), "다른 사용자가 읽을 수 있다") {
		t.Fatalf("까닭을 권한이라고 적지 않았다: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.LoadPSK("srv-b"); err != nil || !ok {
		t.Fatalf("바른 키를 거절했다: %v", err)
	}
}
