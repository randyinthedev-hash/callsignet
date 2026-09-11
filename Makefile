# 실험 실행 진입점. 대부분 root 권한을 요구한다.

CK := poc/cryptokey

.PHONY: help
help:
	@echo "build       csa를 만든다"
	@echo "test        시험을 돌린다"
	@echo "tunnel      csa 둘이 터널을 세우는지 확인       (sudo)"
	@echo "build-static  Rocky에서도 도는 csa를 만든다"
	@echo "dist        설치 묶음을 만든다 (dist/out/csa-linux-amd64.tar.gz)"
	@echo "vm          VM 둘에서 리졸버 갈래를 확인          (sudo)"
	@echo "vm-teardown VM 정리                              (sudo)"
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

.PHONY: build build-static dist test tunnel vm vm-teardown
build:
	go build -o csa ./cmd/csa
test:
	go vet ./...
	go test ./...
tunnel:
	poc/tunnel/run.sh

build-static:
	CGO_ENABLED=0 go build -o csa-static ./cmd/csa

# 태그 워크플로가 붙이는 것과 같은 모양의 묶음이다. 소스에서 만들어 설치하는
# 사람도 같은 절차로 설치할 수 있게 한다.
dist:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-w" -o dist/out/csa ./cmd/csa
	dist/pack.sh dist/out/csa amd64 dist/out
	rm -f dist/out/csa

vm:
	poc/vm/run.sh

vm-teardown:
	poc/vm/run.sh --teardown
