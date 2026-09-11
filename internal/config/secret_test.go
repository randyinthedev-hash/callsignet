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

// TestSecrets파일을한번만읽는다는 설정 검사와 wg 설정이 같은 바이트를 쓰는지
// 본다.
//
// 앞서는 검사가 개인키를 읽어 공개키 짝을 보고, 기동이 같은 경로를 다시 읽어
// wg에 넣었다. 그 사이에 파일이 바뀌면 짝을 확인한 키와 실제로 쓰는 키가 다른
// 것이 된다.
func TestSecrets파일을한번만읽는다(t *testing.T) {
	path := secretFile(t, "private.key", "처음\n")
	c := &Config{Self: Self{PeerID: "srv-a", PrivateKey: path}}
	if got := c.Secrets().Private; got != "처음" {
		t.Fatalf("처음 읽은 것이 다르다: %q", got)
	}
	if err := os.WriteFile(path, []byte("나중\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.Secrets().Private; got != "처음" {
		t.Fatalf("파일을 다시 읽었다. 검사한 키와 쓰는 키가 갈린다: %q", got)
	}
}

// TestReadSecret남이고칠수있는자리를거절한다는 파일이 놓인 자리까지 보는지 본다.
//
// 파일 자체가 0600이고 임자가 맞아도, 그 파일이 놓인 디렉터리를 남이 고칠 수
// 있으면 그 사람이 파일을 통째로 갈아 끼울 수 있다.
func TestReadSecret남이고칠수있는자리를거절한다(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "열린자리")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	// Mkdir는 umask에 걸리므로 권한을 다시 건다.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "private.key")
	if err := os.WriteFile(path, []byte("내용\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSecret("개인키", path)
	if err == nil {
		t.Fatal("남이 고칠 수 있는 자리에 둔 비밀 파일을 받아들였다")
	}
	if !strings.Contains(err.Error(), "다른 사용자가 고칠 수 있다") {
		t.Fatalf("까닭을 자리의 권한이라고 적지 않았다: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret("개인키", path); err != nil {
		t.Fatalf("자리를 닫았는데 거절했다: %v", err)
	}
}

// TestReadSecret상위디렉터리의링크도본다는 마지막 조각만 보지 않는지 본다.
//
// O_NOFOLLOW는 경로의 마지막 조각만 지킨다. 가운데 조각이 링크면 csa는 그것을
// 따라간다. 따라간 끝이 남이 고칠 수 있는 자리이면 거절해야 한다.
func TestReadSecret상위디렉터리의링크도본다(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "진짜")
	if err := os.Mkdir(real, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(real, "private.key")
	if err := os.WriteFile(path, []byte("내용\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "링크")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSecret("개인키", filepath.Join(link, "private.key"))
	if err == nil {
		t.Fatal("링크를 따라간 끝의 자리를 보지 않았다")
	}
	if !strings.Contains(err.Error(), "다른 사용자가 고칠 수 있다") {
		t.Fatalf("까닭을 자리의 권한이라고 적지 않았다: %v", err)
	}
}

// TestLoadPSK자리가아직없으면없는것으로본다는 사전 공유키를 둘 자리가 아직
// 만들어지지 않은 설정을 본다.
//
// psk.mode가 optional이면 키가 없는 것은 잘못이 아니다. 그 자리의 디렉터리가
// 아직 없는 것도 마찬가지다. 비밀 파일이 놓인 자리를 보는 검사를 여는 것보다
// 먼저 하면 그 둘을 가리지 못해, 키를 아직 나르지 않은 머신에서 csa가 뜨지
// 못한다.
func TestLoadPSK자리가아직없으면없는것으로본다(t *testing.T) {
	c := &Config{
		Self:  Self{PeerID: "srv-a", PSK: PSK{Dir: filepath.Join(t.TempDir(), "아직없다")}},
		Peers: []Peer{{PeerID: "srv-a"}, {PeerID: "srv-b"}},
	}
	key, ok, err := c.LoadPSK("srv-b")
	if err != nil {
		t.Fatalf("자리가 없는 것을 잘못으로 보았다: %v", err)
	}
	if ok || key != "" {
		t.Fatalf("없는 키를 있다고 했다: %q", key)
	}
}
