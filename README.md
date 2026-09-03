# Callsignet

기업 안에서 도는 머신과 서비스가 서로를 알아보고 인증하는 일을 네트워크 계층이 맡는다. 앱은 상대를 IP 주소가 아니라 이름으로 부르고 연결이 맺어지는 순간에 상대가 누구인지 확정된다.

설계는 [design/README.md](design/README.md)에 있다. 작성 중이다.

csa는 운영자가 적은 로컬 설정 파일로 움직인다. 머신마다 하나 돌며 터널을 운영하고, 이름을 해석하고, 정책을 집행한다.

## 라이선스

[Apache License 2.0](LICENSE)이다.

## 실험

설계가 주장하는 것을 관측으로 만든다. 지금은 하나다. 받는 쪽 csa가 허용 목록 밖의 출발지로 온 패킷을 버리는지 확인한다.

실행은 ubuntu-dev에서 한다. Mac에서는 설계와 분석만 한다.

```bash
make preflight
```

준비물과 절차는 [poc/README.md](poc/README.md)에 적었다.
