# 실험

설계가 주장하는 것을 관측으로 만든다. 실행은 ubuntu-dev에서 한다. Mac에서는 돌리지 않는다.

## cryptokey routing 확인

설계는 받는 쪽 csa가 상대를 확정한다고 말한다. 그 근거는 wg의 동작이다. wg는 복호화한 패킷의 출발지 IP가 그 상대에게 허용된 목록 안에 없으면 버린다. 그래서 상대의 정적 공개키로 인증된 세션이라도 배정된 터널 IP만 출발지로 쓸 수 있다.

이 실험은 그것을 잰다. 네임스페이스 둘을 만들어 wg로 잇고, 허용된 출발지와 허용 목록 밖 출발지로 각각 패킷을 보낸 뒤 받는 쪽 `wg0`의 통계가 어떻게 갈리는지 본다. 허용 목록 밖에서 온 패킷은 `rx_packets`를 올리지 않고 `rx_errors`만 올린다.

```bash
sudo apt update && sudo apt install -y wireguard-tools iproute2 iputils-ping
make preflight
sudo make setup
sudo make check
sudo make teardown
```

기록은 `results/cryptokey-<시각>.md`로 저절로 만들어진다. 키는 `poc/cryptokey/_work/`에 남으며 커밋하지 않는다.
