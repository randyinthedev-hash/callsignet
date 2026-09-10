package config

import (
	"errors"
	"fmt"
	"io"
	"os"
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
