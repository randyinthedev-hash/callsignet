# Callsignet

기업 안에서 도는 머신과 서비스가 서로를 알아보고 인증하는 일을 네트워크 계층이 맡는다. 앱은 상대를 IP 주소가 아니라 이름으로 부르고 연결이 맺어지는 순간에 상대가 누구인지 확정된다.

설계는 [design/README.md](design/README.md)에 있다. 작성 중이다.

csa는 운영자가 적은 로컬 설정 파일로 움직인다. 머신마다 하나 돌며 터널을 운영하고, 이름을 해석하고, 정책을 집행한다.

## 라이선스

[Apache License 2.0](LICENSE)이다.

## 만들기와 돌리기

Go 1.26 이상이 필요하다. csa는 리눅스에서만 돈다. TUN 인터페이스를 만들고 경로를 넣으므로 네트워크 관리 권한이 필요하다. 직통 경로를 닫는 데 `nft` 명령을 쓰므로 nftables도 있어야 한다. 닫지 않으려면 `csa.toml`에 `guard.mode = "off"`를 둔다.

```bash
make build     # csa를 만든다
make test      # 시험을 돌린다
```

| 명령 | 하는 일 |
|---|---|
| `csa check -c <디렉터리>` | 설정을 읽고 검사한다 |
| `csa genkey -o <파일>` | 정적 키쌍을 만든다 |
| `csa run -c <디렉터리>` | TUN 인터페이스를 만들고 돈다 |
| `csa status -c <디렉터리>` | 도는 csa의 상태와 상대들을 보여 준다 |
| `csa reload -c <디렉터리>` | 도는 csa에게 설정을 다시 읽으라고 이른다 |

설정 파일 셋을 어떻게 적는지는 [design/README.md](design/README.md)의 설정 절에 있다. 무엇을 어떻게 확인하는지는 [TESTING.md](TESTING.md)에 있다.

## 통합 하네스

네임스페이스로 머신 셋을 만들어 csa 둘을 실제로 띄우고, 터널부터 이름 해석과 정책 집행까지 확인한다. root가 필요하다.

```bash
sudo make tunnel
```

무엇을 확인하는지는 [TESTING.md](TESTING.md)에 있다.

## 실험

설계가 주장하는 것을 관측으로 만든다. 지금은 하나다. 받는 쪽 csa가 허용 목록 밖의 출발지로 온 패킷을 버리는지 확인한다.

```bash
sudo make cryptokey
```

준비물과 절차는 [poc/README.md](poc/README.md)에 적었다.
