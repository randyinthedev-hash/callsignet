# 설치와 올리기와 되돌리기: Callsignet

이 문서는 운영자가 csa를 설치하고, 새 판으로 올리고, 앞 판으로 되돌리는 절차다. 설정 파일 셋을 어떻게 적는지는 [design/README.md](design/README.md)의 설정 절에 있다. 여기서는 그것을 어디에 어떤 권한으로 두는지만 적는다.

절차는 설치 묶음에 든 `install.sh`가 밟는다. 운영자가 손으로 밟아도 같은 결과가 나오도록 스크립트가 무엇을 하는지 아래에 모두 적는다.

## 설치 묶음

[릴리스](https://github.com/randyinthedev-hash/callsignet/releases)에서 아키텍처에 맞는 묶음을 받는다. `csa-linux-amd64.tar.gz`와 `csa-linux-arm64.tar.gz`가 있다. 묶음 안에는 다음이 들어 있다.

| 파일 | 무엇 |
|---|---|
| `bin/csa` | 정적으로 링크한 실행 파일 |
| `csa.service` | systemd 서비스 파일 |
| `install.sh` | 이 문서의 절차를 밟는 스크립트 |
| `INSTALL.md` | 이 문서 |
| `LICENSE`, `THIRD-PARTY-NOTICES.md` | 라이선스 |

받은 묶음은 `sha256sum.txt`로 먼저 확인한다.

```bash
sha256sum -c --ignore-missing sha256sum.txt
tar -xzf csa-linux-amd64.tar.gz
cd csa-linux-amd64
```

## 무엇이 어디에 놓이나

| 자리 | 무엇 | 임자와 권한 |
|---|---|---|
| `/opt/callsignet/versions/<판>/` | 묶음을 푼 그대로. 판마다 하나. 실행 파일은 `bin/csa` | root, 0755 |
| `/opt/callsignet/current` | 지금 도는 판을 가리키는 심볼릭 링크 | root |
| `/opt/callsignet/previous` | 바로 앞 판을 가리키는 심볼릭 링크. 되돌릴 때 쓴다 | root |
| `/usr/local/bin/csa` | `current/bin/csa`를 가리키는 링크. 운영자가 `csa status`를 칠 때 쓴다 | root |
| `/etc/systemd/system/csa.service` | `current/csa.service`의 사본 | root, 0644 |
| `/etc/callsignet/` | 설정 셋과 키 | root, **0750** |
| `/etc/callsignet/private.key` | 정적 개인키 | root, **0600** |
| `/etc/callsignet/psk/` | 사전 공유키 | root, **0700** |
| `/run/callsignet/` | `csa status`를 받는 소켓. systemd가 만들고 지운다 | root, 0755 |

판마다 자기 디렉터리에 두고 링크 하나로 어느 판이 도는지 정한다. 올리는 것은 링크를 옮기는 것이고 되돌리는 것도 링크를 옮기는 것이다. 실행 파일을 덮어쓰는 순간이 없다.

실행 파일이 `bin/` 아래에 있는 까닭은 SELinux다. RHEL 계열은 SELinux가 켜져 있고, systemd는 정책이 실행 파일로 아는 문맥(`bin_t`)의 파일만 띄운다. 기본 정책이 `/opt/*/bin/` 아래의 파일에 그 문맥을 붙이므로 정책을 따로 만들지 않아도 된다. `install.sh`는 판을 옮긴 뒤 `restorecon`으로 문맥을 그 자리의 기본값으로 되돌린다. 묶음을 홈 디렉터리에서 풀었으면 그 문맥이 딸려 오는데, 그것으로는 systemd가 띄우지 못한다.

## 서비스 계정과 권한

**csa는 root로 돈다.** TUN 인터페이스를 만들고, 터널 IP와 경로를 넣고, nftables 표를 걸고, `/etc/resolv.conf`를 고치거나 systemd-resolved에 등록하는 데 그 권한이 필요하다. 권한을 내려놓는 것은 아직 만들지 않았다.

그 대신 `csa.service`가 손댈 자리를 좁힌다. `/usr`와 `/boot`는 읽기 전용이고, 홈 디렉터리는 보이지 않고, 장치는 `/dev/net/tun`만 보이며, 새 권한을 얻지 못한다. `/etc`는 그대로 둔다. csa가 `/etc/resolv.conf`를 고치기 때문이다.

csa는 비밀 파일을 읽을 때 그 파일이 일반 파일인지, 임자가 root인지, 다른 사용자가 읽을 수 있는지, 그 파일이 놓인 자리를 다른 사용자가 고칠 수 있는지 본다. 위 표의 권한대로 두면 지난다. 그보다 느슨하면 csa는 어느 파일이 어떻게 어긋났는지 적고 뜨지 않는다.

## 준비물

- 리눅스. systemd가 있어야 한다.
- nftables의 `nft` 명령. Ubuntu에는 처음부터 있고 RHEL 계열은 `dnf install nftables`로 설치한다. 직통 경로를 닫지 않으려면 `csa.toml`에 `guard.mode = "off"`를 둔다.
- RHEL 계열은 firewalld가 wg 포트를 막는다. `firewall-cmd --add-port=51820/udp --permanent && firewall-cmd --reload`로 연다.

## 처음 설치

```bash
sudo ./install.sh install
```

스크립트가 하는 일은 이렇다.

1. `bin/csa version`이 말하는 판으로 `/opt/callsignet/versions/<판>/`을 만들고 묶음을 그대로 옮긴다. **임자를 root로, 권한을 다른 사용자가 쓸 수 없게 못박는다.** 묶음을 일반 사용자가 풀었으면 푼 파일의 임자가 그 사용자인데, 그것을 그대로 옮기면 root로 도는 실행 파일을 그 사용자가 고칠 수 있다. SELinux가 있으면 문맥을 되돌린다.
2. `/opt/callsignet/current`가 그것을 가리키게 한다.
3. `/usr/local/bin/csa`가 `current/bin/csa`를 가리키게 한다.
4. `/etc/callsignet/`을 0750으로 만든다. 채우지는 않는다.
5. `csa.service`를 `/etc/systemd/system/`에 놓고 `systemctl enable csa`를 한다.

**스크립트는 서비스를 띄우지 않는다.** 설정이 아직 없기 때문이다. `csa.service`는 `/etc/callsignet/csa.toml`이 없으면 뜨지 않는다.

2번부터 5번 사이에서 실패하면 스크립트는 만든 것을 치우고 멈춘다. 판 디렉터리와 링크 둘과 서비스 파일이다. `/etc/callsignet/`은 둔다. 그래서 까닭을 고치고 다시 `install`을 할 수 있다. 반쯤 설치된 채로 두면 다시 `install`도 `upgrade`도 거절하기 때문이다.

이어서 운영자가 한다.

```bash
sudo csa genkey -o /etc/callsignet/private.key      # 정적 키쌍. 공개키를 찍는다
sudo install -d -m 700 /etc/callsignet/psk
# csa.toml과 peers.toml과 policy.toml을 /etc/callsignet/ 에 둔다
sudo csa check -c /etc/callsignet
sudo systemctl start csa
sudo csa status -c /etc/callsignet
```

`csa check`가 지나야 `systemctl start`를 한다. 지나지 않으면 csa는 어긋난 곳을 모두 적고 뜨지 않는다.

## 기동과 멈춤과 다시 읽기

| 하고 싶은 것 | 명령 |
|---|---|
| 띄운다 | `systemctl start csa` |
| 멈춘다 | `systemctl stop csa` |
| 설정을 다시 읽는다 | `systemctl reload csa` 또는 `csa reload -c /etc/callsignet` |
| 상태를 본다 | `csa status -c /etc/callsignet` |
| 로그를 본다 | `journalctl -u csa` |

멈추면 csa가 터널을 닫고, 직통 경로 규칙을 지우고, 이름 해석 설정을 되돌린다. 20초 안에 끝나지 않으면 systemd가 끊는다.

**csa가 스스로 멈추는 자리가 하나 있다.** 설정을 다시 읽다 실패하고 되돌리지도 못하면 csa는 터널을 닫고 0이 아닌 값으로 끝난다. 그때 직통 경로 규칙은 일부러 남긴다. `csa.service`의 `Restart=on-failure`가 csa를 다시 띄우고, 다시 뜬 csa는 설정 파일에서 처음부터 다시 건다. 이것이 설계 문서의 「되돌리지도 못하면 csa는 멈춘다」가 전제하는 것이다.

다시 띄워도 곧바로 또 죽기를 10초 안에 다섯 번 되풀이하면 systemd가 그 유닛의 기동을 막는다. `systemctl status csa`에 `start-limit-hit`가 보인다. 까닭을 고친 뒤 `systemctl reset-failed csa`로 풀고 `systemctl start csa`를 한다. `install.sh`는 판을 옮기며 다시 띄우기 전에 이것을 스스로 푼다. 앞 판이 되풀이해 죽은 값을 좋은 판이 치르지 않게 하려는 것이다.

`peers.toml`과 `policy.toml`과 사전 공유키는 도는 중에 갈아 끼우고 `reload`를 하면 된다. `csa.toml`은 그럴 수 없다. 거기 적힌 값은 TUN 인터페이스와 개인키와 리슨 주소를 정한다. 그것을 바꾸면 `systemctl restart csa`를 한다.

## 올리기

새 묶음을 받아 풀고 그 자리에서 부른다.

```bash
sudo ./install.sh upgrade
```

스크립트가 하는 일은 이렇다.

1. 새 판을 `/opt/callsignet/versions/<새 판>/`에 둔다. 옆의 임시 자리에 다 만든 뒤 한 번에 옮긴다. 임시 자리의 이름은 점으로 시작해 어떤 판 이름과도 겹치지 않는다. 지금 도는 판은 건드리지 않는다. 같은 판의 디렉터리가 이미 있으면 치우고 다시 둔다. 앞서 걸려 멈춘 시도가 남긴 것이다. 그래서 같은 묶음으로 다시 시도할 수 있다.
2. **새 판의 csa로 지금 설정을 검사한다.** `versions/<새 판>/bin/csa check -c /etc/callsignet`이다. 설정 파일의 모양이 판마다 달라질 수 있다. 여기서 걸리면 두었던 디렉터리를 치우고 아무것도 바꾸지 않고 멈춘다.
3. `previous`가 지금 판을, `current`가 새 판을 가리키게 한다. 서비스 파일도 새 판의 것으로 바꾼다.
4. 서비스가 돌고 있으면 `systemctl restart csa`를 한다.
5. **15초 안에 `csa status`가 답하는지 본다.** 답하면 끝이다.
6. 답하지 않으면 **시도하기 전 그대로 돌아온다.** `current`도 `previous`도 서비스 파일도 시도 전 값으로 되돌리고 다시 띄우고 답하는지 다시 본다. `systemctl restart` 자체가 실패한 것도 답하지 않는 것으로 본다. systemd가 실행 파일을 띄우지조차 못하는 자리가 그렇다. 무엇이 잘못됐는지는 `journalctl -u csa`에 남는다.

3번에서 링크를 옮긴 뒤 서비스 파일을 쓰지 못해도 같다. 시도 전 그대로 돌아오고 아무것도 바뀌지 않았다고 말한다.

**돌아오지도 못하면 스크립트는 「돌아왔다」고 하지 않는다.** 「반쯤 옮겨진 상태」라고 말하고, `current`와 `previous`가 무엇을 가리키는지, 서비스 파일이 지금 판의 것인지, 서비스가 도는지를 그대로 적고 2로 끝난다. 그때는 운영자가 `systemctl stop csa`로 서비스를 멈추고, 까닭을 치우고, 마지막으로 돌던 판의 묶음으로 `upgrade`를 하거나 `rollback`을 한 뒤, `systemctl reset-failed csa`로 실패 상태를 풀고 `systemctl start csa`를 한다. `./install.sh status`가 지금 링크와 서비스 파일이 맞는지 보여 준다.

스크립트는 묶음의 `bin/csa version`이 말하는 값을 판 이름으로 쓴다. 그 값이 비어 있거나 `.`이나 `..`이거나 슬래시가 들어 있으면 아무것도 바꾸지 않고 거절한다. 판 이름이 디렉터리 이름이 되고 그 디렉터리를 지우기도 하기 때문이다.

다시 띄우는 동안 터널이 잠깐 끊긴다. 이미 맺어진 연결은 csa가 다시 뜬 뒤 wg가 세션을 다시 맺으면 이어진다. 몇 초 걸린다.

서비스가 돌고 있지 않으면 링크만 옮기고 끝낸다.

## 되돌리기

```bash
sudo ./install.sh rollback
```

올리기와 같은 길을 거꾸로 밟는다. **앞 판의 csa로 지금 설정을 먼저 검사한다.** 새 판에 맞춰 설정을 고쳤다면 앞 판이 그것을 받지 않을 수 있고, 그때는 옮기기 전에 멈춘다. 지나면 `current`와 `previous`를 맞바꾸고, 서비스 파일을 앞 판의 것으로 되돌리고, 돌고 있으면 다시 띄우고 답하는지 본다. **앞 판이 뜨지 않거나 답하지 않으면 시도하기 전 그대로 돌아온다.** 돌아오지도 못하면 올리기와 같이 반쯤 옮겨진 상태라고 말한다. 앞 판의 디렉터리가 그대로 있으므로 내려받을 것이 없다.

되돌릴 수 있는 것은 바로 앞 판 하나다. 그보다 앞으로 가려면 그 판의 묶음으로 `upgrade`를 다시 한다. 판 번호가 낮아져도 `upgrade`다. 스크립트는 판의 높낮이를 따지지 않고 「지금과 다른 판으로 옮기는 것」만 한다.

## 어느 판이 도는지 보기

```bash
sudo ./install.sh status      # 지금 판, 앞 판, 둔 판, 서비스 상태
csa version                   # /usr/local/bin/csa 가 가리키는 판
```

`csa version`이 찍는 값과 릴리스 노트의 판이 같아야 한다. 태그 워크플로가 그것을 보고 붙인다.

## 지우기

```bash
sudo systemctl disable --now csa
sudo rm -f /etc/systemd/system/csa.service /usr/local/bin/csa
sudo systemctl daemon-reload
sudo rm -rf /opt/callsignet
```

`/etc/callsignet/`은 지우지 않는다. 거기에 이 머신의 개인키가 있다. 지울지는 운영자가 정한다.
