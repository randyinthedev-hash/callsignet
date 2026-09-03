// Package control은 도는 csa에게 묻는 통로다.
//
// csa run이 유닉스 소켓을 하나 열고, csa status가 거기 붙어 묻는다. 물음은 한
// 줄이고 답은 두 부분이다. 첫 줄이 ok 또는 error이고 그 뒤가 본문이다.
//
// 소켓은 머신마다 하나가 아니라 peer-id마다 하나다. 설정 디렉터리를 달리해 한
// 머신에서 csa를 여럿 띄우는 경우가 있기 때문이다. 통합 하네스가 그렇게 한다.
package control

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const dirPath = "/run/callsignet"

// SocketPath는 그 peer-id로 도는 csa의 소켓 경로다.
func SocketPath(peerID string) string {
	return filepath.Join(dirPath, peerID+".sock")
}

// Server는 열려 있는 소켓이다.
type Server struct {
	ln     net.Listener
	answer func(req string) (string, error)
}

// Listen은 소켓을 열고 물음을 받기 시작한다. 소유자만 붙을 수 있다.
func Listen(peerID string, answer func(req string) (string, error)) (*Server, error) {
	path := SocketPath(peerID)
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		return nil, fmt.Errorf("소켓 디렉터리를 만들지 못했다: %w", err)
	}
	if stale(path) {
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("소켓을 열지 못했다: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("소켓 권한을 걸지 못했다: %w", err)
	}
	s := &Server{ln: ln, answer: answer}
	go s.loop()
	return s, nil
}

// stale은 그 자리에 소켓 파일은 있는데 아무도 듣고 있지 않은지 본다. 앞서 돌던
// csa가 갑자기 죽으면 파일이 남고, 그러면 새 csa가 소켓을 열지 못한다.
func stale(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return true
	}
	c.Close()
	return false
}

// Close는 소켓을 닫는다. 닫으면서 소켓 파일도 지운다.
func (s *Server) Close() {
	if s != nil && s.ln != nil {
		s.ln.Close()
	}
}

func (s *Server) loop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // 닫혔다
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	req, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	body, err := s.answer(strings.TrimSpace(req))
	if err != nil {
		fmt.Fprintf(c, "error\n%v\n", err)
		return
	}
	fmt.Fprintf(c, "ok\n%s", body)
}

// Ask는 도는 csa에게 물어 답의 본문을 돌려준다.
func Ask(peerID, req string) (string, error) {
	path := SocketPath(peerID)
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("도는 csa에 붙지 못했다. csa run이 돌고 있는지 보라: %s", path)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, req); err != nil {
		return "", fmt.Errorf("물음을 보내지 못했다: %w", err)
	}
	br := bufio.NewReader(c)
	head, err := br.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("답을 받지 못했다: %w", err)
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return "", fmt.Errorf("답을 다 받지 못했다: %w", err)
	}
	if strings.TrimSpace(head) != "ok" {
		return "", fmt.Errorf("csa가 답하지 못했다: %s", strings.TrimSpace(string(body)))
	}
	return string(body), nil
}
