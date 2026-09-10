package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteSecret이미있으면만들지않는다는 쓰던 신원 키를 조용히 덮어쓰지 않게
// 하려는 것이다.
func TestWriteSecret이미있으면만들지않는다(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
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
// 있다고 찍는 일이 있었다.
func TestWriteSecret덮어쓸때권한을바로잡는다(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
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

// TestWriteSecret새로만들때권한은 새로 만드는 자리도 0600인지 본다.
func TestWriteSecret새로만들때권한(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.key")
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
		// 하나가 실패해도 나머지는 밟아야 반쯤 걸린 자리가 좁아진다.
		if n != 3 {
			t.Fatalf("실패한 뒤 나머지를 멈췄다: %d", n)
		}
	})
}
