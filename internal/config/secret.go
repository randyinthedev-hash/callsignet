package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// secretLimit은 비밀 파일에서 읽어 들이는 크기의 한계다. 개인키와 사전 공유키는
// base64로 44글자다. 그보다 훨씬 큰 파일을 통째로 읽을 까닭이 없다.
const secretLimit = 4096

// ReadSecret은 비밀을 담은 파일을 한 번만 열어, 그 파일 설명자에서 검사하고
// 같은 설명자로 내용을 읽는다.
//
// 경로로 검사한 뒤에 경로로 다시 여는 것은 안전하지 않다. 상위 디렉터리를 다른
// 사용자가 고칠 수 있으면 그 사이에 파일이나 심볼릭 링크를 갈아 끼울 수 있다.
// 그러면 csa는 검사한 것과 다른 파일을 읽는다. 그래서 여기서는 한 번만 열고
// 그 설명자만 쓴다.
//
// O_NOFOLLOW는 경로의 마지막 조각이 심볼릭 링크면 열지 않는다. O_NONBLOCK은
// FIFO나 장치 파일을 열 때 csa가 멈추지 않게 한다. FIFO는 일반 파일이 아니므로
// 검사에서 걸린다. csa는 거기서 멈추지 않고 까닭을 적고 나온다.
func ReadSecret(kind, path string) ([]byte, error) {
	// 파일 자체의 임자와 권한만 보아서는 모자란다. 그 파일이 놓인 디렉터리를
	// 남이 고칠 수 있으면 그 사람이 파일을 통째로 갈아 끼울 수 있다.
	if err := safePath(kind, path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err // 없는 것 자체가 잘못인지는 부르는 쪽이 정한다
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s 자리가 심볼릭 링크다: %s", kind, path)
		}
		return nil, fmt.Errorf("%s 파일을 열 수 없다: %s", kind, path)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s 파일을 볼 수 없다: %s", kind, path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s 자리가 일반 파일이 아니다: %s", kind, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s 파일을 다른 사용자가 읽을 수 있다. 0600으로 두라: %s (지금 %o)",
			kind, path, perm)
	}
	// 권한만 보아서는 모자란다. 0600이어도 임자가 남이면 그 사람이 언제든
	// 내용을 바꿀 수 있다. csa는 root로 도므로 root의 것이거나 csa를 돌리는
	// 사용자의 것이어야 한다.
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if uid := os.Getuid(); int(st.Uid) != uid && st.Uid != 0 {
			return nil, fmt.Errorf("%s 파일의 임자가 다르다: %s (임자 %d, 이 csa %d)",
				kind, path, st.Uid, uid)
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, secretLimit+1))
	if err != nil {
		return nil, fmt.Errorf("%s 파일을 읽지 못했다: %s", kind, path)
	}
	if len(b) > secretLimit {
		return nil, fmt.Errorf("%s 파일이 너무 크다. %d바이트를 넘는다: %s", kind, secretLimit, path)
	}
	return b, nil
}

// safePath는 비밀 파일이 놓인 자리와 그 위의 디렉터리를 모두 본다.
//
// O_NOFOLLOW는 경로의 마지막 조각만 지킨다. `/etc/cs/private.key`에서 `cs`가
// 심볼릭 링크면 csa는 그 링크를 따라간다. 그래서 적은 그대로의 자리와 링크를
// 모두 푼 자리를 둘 다 훑는다. 남이 고칠 수 있는 디렉터리가 하나라도 있으면
// 그 사람이 링크를 다른 곳으로 돌리거나 파일을 갈아 끼울 수 있다.
//
// 디렉터리의 임자까지는 보지 않는다. csa를 root로 돌리면서 키를 운영자의 홈
// 아래에 두는 것이 흔한데, 그 자리를 임자가 바꿀 수 있는 것은 막지 못한다.
func safePath(kind, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%s 파일의 자리를 읽을 수 없다: %s", kind, path)
	}
	dirs := []string{filepath.Dir(abs)}
	// EvalSymlinks는 경로의 모든 조각에서 링크를 푼다. 푼 자리가 다르면 그
	// 자리도 훑는다. 링크를 따라간 끝이 남의 자리일 수 있다.
	if real, err := filepath.EvalSymlinks(dirs[0]); err == nil && real != dirs[0] {
		dirs = append(dirs, real)
	}
	for _, dir := range dirs {
		for {
			if err := safeDir(kind, dir); err != nil {
				return err
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return nil
}

// safeDir는 디렉터리 하나를 본다.
//
// 끈적임 비트가 선 디렉터리는 누구나 쓸 수 있어도 남의 항목을 지우거나 이름을
// 바꾸지 못한다. `/tmp`가 그렇다. 그래서 그 자리는 거절하지 않는다.
func safeDir(kind, dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%s 파일이 놓인 자리를 볼 수 없다: %s", kind, dir)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		// 심볼릭 링크 자신의 권한은 리눅스에서 뜻이 없다. 이 링크를 남이 바꿀
		// 수 있는지는 링크가 놓인 자리가 정하고, 그 자리는 이 반복이 따로 본다.
		return nil
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s 파일이 놓인 자리가 디렉터리가 아니다: %s", kind, dir)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%s 파일이 놓인 자리를 다른 사용자가 고칠 수 있다. 0755로 두라: %s (지금 %o)",
			kind, dir, perm)
	}
	return nil
}
