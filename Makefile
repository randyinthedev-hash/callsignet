# 실험 실행 진입점. 대부분 root 권한을 요구한다.

CK := poc/cryptokey

.PHONY: help
help:
	@echo "build       csa를 만든다"
	@echo "test        시험을 돌린다"
	@echo "tunnel      csa 둘이 터널을 세우는지 확인       (sudo)"
	@echo "preflight   준비물 점검 (root 불필요)"
	@echo "setup       네임스페이스 둘을 만들고 wg로 잇는다  (sudo)"
	@echo "check       허용 목록 밖 출발지가 버려지는지 확인  (sudo)"
	@echo "teardown    네임스페이스 정리                      (sudo)"
	@echo "cryptokey   preflight→setup→check→teardown        (sudo)"

.PHONY: preflight setup check teardown cryptokey
preflight:
	$(CK)/preflight.sh
setup:
	$(CK)/setup.sh
check:
	$(CK)/check.sh
teardown:
	$(CK)/teardown.sh

cryptokey: preflight
	$(CK)/setup.sh
	$(CK)/check.sh
	$(CK)/teardown.sh

.PHONY: build test tunnel
build:
	go build -o csa ./cmd/csa
test:
	go vet ./...
	go test ./...
tunnel:
	poc/tunnel/run.sh
