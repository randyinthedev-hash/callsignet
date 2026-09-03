package control

import (
	"strings"
	"testing"
)

// 소켓을 열고 붙어 묻는 것까지 한 번에 본다. 유닉스 소켓이므로 네트워크가
// 필요 없고 root도 필요 없다. 다만 /run/callsignet에 쓸 수 있어야 하므로
// 그러지 못하면 건너뛴다.
func TestAskAndAnswer(t *testing.T) {
	srv, err := Listen("csn-test", func(req string) (string, error) {
		if req == "status" {
			return `{"peer-id":"csn-test"}`, nil
		}
		return "", errUnknown(req)
	})
	if err != nil {
		t.Skipf("소켓을 열 수 없다: %v", err)
	}
	defer srv.Close()

	got, err := Ask("csn-test", "status")
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"peer-id":"csn-test"}` {
		t.Errorf("답이 다르다: %s", got)
	}

	if _, err := Ask("csn-test", "모르는것"); err == nil {
		t.Error("모르는 물음은 오류여야 한다")
	} else if !strings.Contains(err.Error(), "모르는것") {
		t.Errorf("무엇이 문제인지 적어야 한다: %v", err)
	}
}

func TestAskWithNobodyListening(t *testing.T) {
	_, err := Ask("csn-없는것", "status")
	if err == nil {
		t.Fatal("돌고 있지 않으면 오류여야 한다")
	}
	if !strings.Contains(err.Error(), "csa run") {
		t.Errorf("무엇을 하라는 것인지 알려야 한다: %v", err)
	}
}

type errUnknownType string

func (e errUnknownType) Error() string { return "모르는 물음이다: " + string(e) }

func errUnknown(req string) error { return errUnknownType(req) }
