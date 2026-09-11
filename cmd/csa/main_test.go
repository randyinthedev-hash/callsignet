package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/randyinthedev-hash/callsignet/internal/config"
	"github.com/randyinthedev-hash/callsignet/internal/guard"
	"github.com/randyinthedev-hash/callsignet/internal/name"
)

// TestWriteSecret이미있으면만들지않는다는 쓰던 신원 키를 조용히 덮어쓰지 않게
// 하려는 것이다.
func TestWriteSecret이미있으면만들지않는다(t *testing.T) {
	path := filepath.Join(tempDir(t), "private.key")
	if err := writeSecret(path, "첫 키\n", false); err != nil {
		t.Fatalf("새로 만들지 못했다: %v", err)
	}
	err := writeSecret(path, "둘째 키\n", false)
	if err == nil {
		t.Fatal("있는 파일을 덮어썼다")
	}
	if !strings.Contains(err.Error(), "-f") {
		t.Fatalf("덮어쓰는 방법을 알리지 않는다: %v", err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "첫 키\n" {
		t.Fatalf("먼저 있던 것이 바뀌었다: %s", b)
	}
}

// TestWriteSecret덮어쓸때권한을바로잡는다는 os.WriteFile이 이미 있는 파일의
// 권한을 바꾸지 않기 때문이다. 0644인 파일에 개인키를 쓰고도 소유자만 읽을 수
// 있다고 찍는 일이 있었다. 옆에 새로 써서 옮기므로 옛 파일의 권한이 따라오지
// 않는다.
func TestWriteSecret덮어쓸때권한을바로잡는다(t *testing.T) {
	path := filepath.Join(tempDir(t), "psk.key")
	if err := os.WriteFile(path, []byte("남이 만든 파일\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecret(path, "새 키\n", true); err != nil {
		t.Fatalf("덮어쓰지 못했다: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("권한을 바로잡지 않았다: %o", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if string(b) != "새 키\n" {
		t.Fatalf("덮어쓴 내용이 다르다: %s", b)
	}
}

// TestWriteSecret바꾸다실패해도쓰던키를잃지않는다는 있던 파일을 먼저 비우지
// 않기 때문이다. 옆에 온전히 써 두고 한 번에 옮긴다.
func TestWriteSecret바꾸다실패해도쓰던키를잃지않는다(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "psk.key")
	if err := writeSecret(path, "쓰던 키\n", false); err != nil {
		t.Fatal(err)
	}
	// 옆에 쓰지 못하게 디렉터리를 읽기만 되게 한다. root는 권한 검사를
	// 지나므로 그때는 이 자리를 만들 수 없다.
	if os.Getuid() == 0 {
		t.Skip("root로 돌면 권한으로 막을 수 없다")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if err := writeSecret(path, "새 키\n", true); err == nil {
		t.Fatal("바꾸지 못했는데 성공이라고 했다")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "쓰던 키\n" {
		t.Fatalf("쓰던 키를 잃었다: %v %q", err, b)
	}
}

// TestWriteSecret새로만들때권한은 새로 만드는 자리도 0600인지 본다.
func TestWriteSecret새로만들때권한(t *testing.T) {
	path := filepath.Join(tempDir(t), "new.key")
	if err := writeSecret(path, "키\n", false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("소유자만 읽을 수 있게 만들지 않았다: %o", fi.Mode().Perm())
	}
}

// TestRollback은 되돌리기가 실패했을 때 그 사실을 알리는지 본다. 되돌렸다고
// 잘못 알리면 운영자가 이 머신이 옛 설정으로 돈다고 여긴다.
func TestRollback(t *testing.T) {
	cause := errors.New("걸지 못했다")
	quiet := func(string, ...any) {}

	t.Run("모두 되돌리면 되돌렸다고 알린다", func(t *testing.T) {
		n := 0
		step := func() error { n++; return nil }
		err := rollback(cause, quiet, step, step, step)
		if !errors.Is(err, cause) {
			t.Fatalf("까닭을 잃었다: %v", err)
		}
		if !strings.Contains(err.Error(), "되돌렸다") {
			t.Fatalf("되돌렸다고 알리지 않는다: %v", err)
		}
		if errors.Is(err, errMixed) {
			t.Fatal("되돌렸는데 멈추라는 표지를 달았다")
		}
		if n != 3 {
			t.Fatalf("걸음을 다 밟지 않았다: %d", n)
		}
	})

	t.Run("하나라도 실패하면 반쯤 걸렸다고 알린다", func(t *testing.T) {
		n := 0
		ok := func() error { n++; return nil }
		bad := func() error { n++; return fmt.Errorf("되돌리지 못했다") }
		err := rollback(cause, quiet, bad, ok, ok)
		if !strings.Contains(err.Error(), "반쯤 걸린 상태") {
			t.Fatalf("반쯤 걸렸다고 알리지 않는다: %v", err)
		}
		// 알리는 것만으로는 모자란다. 부른 쪽이 이것을 보고 csa를 멈춘다.
		// 어느 판이 걸려 있는지 알 수 없는 채로 계속 돌면 안 되기 때문이다.
		if !errors.Is(err, errMixed) {
			t.Fatalf("멈추라는 표지를 달지 않았다: %v", err)
		}
		// 하나가 실패해도 나머지는 밟아야 반쯤 걸린 자리가 좁아진다.
		if n != 3 {
			t.Fatalf("실패한 뒤 나머지를 멈췄다: %d", n)
		}
	})
}

// 시험에서 쓰는 대역이다. Keep을 불렀는지 센다.
type fakeGuard struct{ kept int }

func (g *fakeGuard) Keep() { g.kept++ }

// TestWaitStop은 멈추는 두 갈래를 본다.
//
// 반쯤 걸린 상태로 멈출 때는 직통 경로 규칙을 남겨야 한다. 지우면 이 머신의
// 서비스 포트가 터널 밖으로 다시 열린다. 신호로 멈출 때는 남기지 않는다.
// 어느 쪽이든 이 함수가 돌아가면 runRun이 끝나고 터널이 닫힌다.
func TestWaitStop(t *testing.T) {
	quiet := func(string, ...any) {}

	t.Run("반쯤 걸리면 규칙을 남기고 멈춘다", func(t *testing.T) {
		mixed := make(chan struct{}, 1)
		mixed <- struct{}{}
		gd := &fakeGuard{}
		err := waitStop(make(chan os.Signal), mixed, gd, quiet)
		if !errors.Is(err, errMixed) {
			t.Fatalf("멈추는 까닭을 알리지 않는다: %v", err)
		}
		if gd.kept != 1 {
			t.Fatalf("직통 경로 규칙을 남기지 않았다: %d", gd.kept)
		}
	})

	t.Run("신호로 멈추면 규칙을 지운다", func(t *testing.T) {
		stop := make(chan os.Signal, 1)
		stop <- syscall.SIGTERM
		gd := &fakeGuard{}
		if err := waitStop(stop, make(chan struct{}), gd, quiet); err != nil {
			t.Fatalf("신호로 멈추는데 오류가 났다: %v", err)
		}
		if gd.kept != 0 {
			t.Fatal("신호로 멈추는데 규칙을 남겼다")
		}
	})
}

// 시험에서 쓰는 대역 셋이다. 진짜 것은 TUN 인터페이스와 nft를 건드린다.
type fakeDevice struct{ reloads int }

func (d *fakeDevice) Reload(*config.Config) error { d.reloads++; return nil }

type fakeResolver struct{ sets int }

func (r *fakeResolver) SetTable(*name.Table) { r.sets++ }

type fakeGate struct{ checks, applies int }

func (g *fakeGate) Check(guard.Config) error { g.checks++; return nil }
func (g *fakeGate) Apply(guard.Config) error { g.applies++; return nil }

// 정해진 값에서 키 짝을 만든다.
func keyPair(t *testing.T, fill byte) (priv, pub string) {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// 설정 한 벌을 만든다. csa reload가 실제로 읽는 파일 셋이다.
func configDir(t *testing.T) (dir string, writePSK func(fill byte)) {
	t.Helper()
	dir = tempDir(t)
	privA, pubA := keyPair(t, 1)
	_, pubB := keyPair(t, 2)

	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("private.key", privA+"\n")
	pskDir := filepath.Join(dir, "psk")
	if err := os.Mkdir(pskDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write("csa.toml", fmt.Sprintf(`peer-id     = "srv-a"
private-key = %q
domain      = "cs.test.internal"
tunnel-cidr = "10.91.0.0/24"
listen-port = 51820

[tun]
name = "cs0"
mtu  = 1420

[dns]
listen = "127.0.53.1:53"

[psk]
dir  = %q
mode = "required"
`, filepath.Join(dir, "private.key"), pskDir))
	write("peers.toml", fmt.Sprintf(`[[peer]]
peer-id    = "srv-a"
public-key = %q
tunnel-ip  = "10.91.0.1"
endpoints  = ["10.90.0.1:51820"]
services   = [{ app = "billing", port = 8080 }]

[[peer]]
peer-id    = "srv-b"
public-key = %q
tunnel-ip  = "10.91.0.2"
endpoints  = ["10.90.0.2:51820"]
services   = [{ app = "report", port = 8080 }]
`, pubA, pubB))
	write("policy.toml", `outbound = ["srv-b/report"]

[[inbound]]
app   = "billing"
allow = ["srv-b"]
`)
	writePSK = func(fill byte) {
		t.Helper()
		key := bytes.Repeat([]byte{fill}, 32)
		body := base64.StdEncoding.EncodeToString(key) + "\n"
		if err := os.WriteFile(filepath.Join(pskDir, "srv-b.key"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, writePSK
}

// TestReload사전공유키를바꾸면다시건다는 운영자가 키를 갈아 끼우고 csa reload를
// 했을 때 csa가 그것을 실제로 거는지 본다.
//
// 사전 공유키는 TOML이 아니라 파일에 있다. 앞서는 csa.toml과 peers.toml과
// policy.toml만 견주어, 키만 바뀐 자리에서 csa가 「바뀐 것이 없습니다」라고
// 답하고 옛 키로 계속 돌았다. 운영자는 새 키가 걸렸다고 여긴다.
//
// 이 시험은 맨 위의 reload를 부른다. wg에 거는 부분만 따로 보면 그 앞에서
// 막히는 이 자리를 잡지 못한다.
func TestReload사전공유키를바꾸면다시건다(t *testing.T) {
	dir, writePSK := configDir(t)
	quiet := func(string, ...any) {}

	writePSK(1)
	old, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p := old.Validate(); len(p) > 0 {
		t.Fatalf("설정이 어긋났다: %v", p)
	}
	// 도는 csa가 쓰는 키다. 여기서 한 번 읽어 둔다.
	if _, ok := old.Secrets().PSK["srv-b"]; !ok {
		t.Fatal("첫 사전 공유키를 읽지 못했다")
	}
	var live atomic.Pointer[config.Config]
	live.Store(old)

	// TOML은 그대로 두고 키만 다른 유효한 값으로 바꾼다.
	writePSK(2)

	dev, res, gd := &fakeDevice{}, &fakeResolver{}, &fakeGate{}
	report, err := reload(dir, &live, dev, res, gd, quiet)
	if err != nil {
		t.Fatalf("다시 읽지 못했다: %v", err)
	}
	if dev.reloads != 1 {
		t.Fatalf("바뀐 키를 wg에 걸지 않았다. Reload를 부른 횟수 %d", dev.reloads)
	}
	if gd.applies != 1 {
		t.Fatalf("직통 경로 규칙을 다시 걸지 않았다: %d", gd.applies)
	}
	if !strings.Contains(report, "사전 공유키를 바꾼 상대: srv-b") {
		t.Fatalf("무엇이 바뀌었는지 알리지 않았다: %q", report)
	}
	if live.Load() == old {
		t.Fatal("새 설정을 걸지 않았다")
	}
	if got := live.Load().Secrets().PSK["srv-b"]; got == old.Secrets().PSK["srv-b"] {
		t.Fatal("옛 키를 그대로 들고 있다")
	}

	// 아무것도 바꾸지 않으면 다시 걸지 않는다.
	report, err = reload(dir, &live, dev, res, gd, quiet)
	if err != nil {
		t.Fatalf("다시 읽지 못했다: %v", err)
	}
	if dev.reloads != 1 {
		t.Fatalf("바뀐 것이 없는데 다시 걸었다: %d", dev.reloads)
	}
	if !strings.Contains(report, "바뀐 것이 없습니다") {
		t.Fatalf("바뀐 것이 없다고 알리지 않았다: %q", report)
	}
}

// tempDir는 비밀 파일을 둘 수 있는 임시 자리다. t.TempDir는 umask를 따르므로
// umask가 002인 머신에서는 그룹이 쓸 수 있는 자리가 되고, 비밀 파일이 놓인
// 자리를 보는 검사가 그것을 거절한다. 두 단계 모두 0755로 맞춘다.
func tempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{dir, filepath.Dir(dir)} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
