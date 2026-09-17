#!/usr/bin/env bash
# 실제 VM 둘에서 csa를 돌려 네임스페이스가 밟지 못하는 것을 확인한다.
#
# 진짜 NIC에서 커널이 목적지가 바뀐 패킷의 경로를 다시 찾는지, 엄격한 역경로
# 검사에서도 되돌아가는 패킷이 지나는지 본다. Ubuntu에는 systemd-resolved가 돌고
# Rocky에는 NetworkManager와 firewalld가 돈다. csa가 그 셋을 건드리지 않고 자기
# 표 둘만 걸고 지우는지 본다. 터널도 진짜 머신 둘 사이에서 확인한다.
set -euo pipefail

NET=cs-vmnet
VM_A=cs-vm-a          # Ubuntu 24.04. systemd-resolved가 돈다
VM_B=cs-vm-b          # Rocky 9. NetworkManager와 firewalld가 돈다
MAC_A=52:54:00:c5:00:0a
MAC_B=52:54:00:c5:00:0b
IP_A=10.98.0.10       # 언더레이
IP_B=10.98.0.30
WG_A=10.99.0.1        # 터널
WG_B=10.99.0.2
CIDR=10.99.0.0/24
PORT=51820
APP_A=billing
APP_B=report

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CSA="${CSA:-}"
WORK="$HERE/_work"
POOL=/var/lib/libvirt/images
IMG_UBUNTU="$POOL/cs-base-ubuntu.qcow2"
IMG_ROCKY="$POOL/cs-base-rocky.qcow2"
URL_UBUNTU=https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img
URL_ROCKY=https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2

. "$HERE/../lib.sh"
RESULTS="$REPO/results"

if [ "$(id -u)" -ne 0 ]; then echo "root가 필요합니다: sudo $0" >&2; exit 1; fi
# 만들어 둔 것을 그냥 쓰면 낡은 바이너리로 시험이 돈다. 부르는 사람이 CSA로
# 자리를 주었을 때만 그것을 쓴다.
if [ -n "$CSA" ]; then
  echo "csa를 새로 만들지 않고 준 것을 씁니다: $CSA"
  [ -x "$CSA" ] || { echo "그 자리에 csa가 없습니다: $CSA" >&2; exit 1; }
else
  CSA="$REPO/csa-static"
  # Rocky는 Ubuntu보다 glibc가 낮아 동적으로 링크한 것은 돌지 않는다.
  build_csa "$REPO" "$CSA" static
fi
if ldd "$CSA" >/dev/null 2>&1; then
  echo "$CSA가 동적으로 링크되어 있습니다. CGO_ENABLED=0으로 만들어야 합니다." >&2
  exit 1
fi

KEEP="${KEEP:-0}"     # KEEP=1이면 확인이 끝나도 VM을 남긴다
cleanup() {
  [ "$KEEP" = 1 ] && { echo; echo "VM을 남깁니다. 지우려면: sudo $0 --teardown"; return; }
  for vm in "$VM_A" "$VM_B"; do
    virsh destroy "$vm" >/dev/null 2>&1 || true
    virsh undefine "$vm" --nvram --remove-all-storage >/dev/null 2>&1 || true
  done
  virsh net-destroy "$NET" >/dev/null 2>&1 || true
  virsh net-undefine "$NET" >/dev/null 2>&1 || true
  rm -f "$POOL/$VM_A.qcow2" "$POOL/$VM_B.qcow2" "$POOL/$VM_A-seed.iso" "$POOL/$VM_B-seed.iso"
}
if [ "${1:-}" = "--teardown" ]; then KEEP=0; cleanup; echo "지웠습니다."; exit 0; fi
trap cleanup EXIT
cleanup
rm -rf "$WORK"; mkdir -p "$WORK"

echo "== 바탕 이미지"
fetch() { # 주소 파일
  if [ -f "$2" ]; then echo "  이미 있습니다: $(basename "$2")"; return; fi
  echo "  받습니다: $(basename "$2")"
  curl -fsSL -o "$2.part" "$1" && mv "$2.part" "$2"
}
fetch "$URL_UBUNTU" "$IMG_UBUNTU"
fetch "$URL_ROCKY" "$IMG_ROCKY"
for img in "$IMG_UBUNTU" "$IMG_ROCKY"; do
  printf '  %-24s %s\n' "$(basename "$img")" \
    "$(qemu-img info "$img" 2>&1 | grep -iE 'file format|virtual size' | tr '\n' ' ')"
done

echo "== 열쇠와 씨앗"
ssh-keygen -q -t ed25519 -N "" -f "$WORK/id" -C csn-vm
PUB=$(cat "$WORK/id.pub")
SSH="ssh -q -i $WORK/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
SCP="scp -q -i $WORK/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# root로 붙는다. csa가 어차피 root 권한이 필요하기 때문이다.
#
# 키를 users 항목이 아니라 write_files로 심는 까닭이 있다. RHEL 계열 이미지는
# cloud-init의 users로 root를 다루지 않는다. SELinux 문맥도 다시 잡아야 한다.
# 그러지 않으면 sshd가 키 파일을 읽지 못한다. sshd 설정은 앞에 오는 이름으로
# 드롭인을 넣어 cloud-init이 넣는 것보다 먼저 읽히게 한다.
seed() { # 이름 바탕이미지 추가명령
  cat > "$WORK/$1-user-data" <<CLOUD
#cloud-config
hostname: $1
disable_root: false
write_files:
  - path: /root/.ssh/authorized_keys
    permissions: "0600"
    owner: "root:root"
    content: |
      $PUB
  - path: /etc/ssh/sshd_config.d/00-csn.conf
    permissions: "0644"
    content: |
      PermitRootLogin prohibit-password
runcmd:
  - [ sh, -c, "chmod 700 /root/.ssh" ]
  - [ sh, -c, "restorecon -R /root/.ssh /etc/ssh 2>/dev/null || true" ]
  - [ sh, -c, "systemctl restart sshd 2>/dev/null || systemctl restart ssh" ]
  - [ sh, -c, "$3" ]
CLOUD
  printf 'instance-id: %s\nlocal-hostname: %s\n' "$1" "$1" > "$WORK/$1-meta-data"
  cloud-localds "$POOL/$1-seed.iso" "$WORK/$1-user-data" "$WORK/$1-meta-data"
  # 크기를 적지 않는다. 바탕 이미지의 크기를 그대로 물려받아야 한다. 더 작게
  # 적으면 디스크가 잘려 파티션 표의 뒷부분과 파일 시스템의 끝이 사라진다.
  # Rocky는 10G이고 Ubuntu는 3.5G라, 8G로 적었더니 Rocky만 부팅하지 못했다.
  qemu-img create -q -f qcow2 -F qcow2 -b "$2" "$POOL/$1.qcow2"
  printf '  %-12s %s\n' "$1" "$(qemu-img info "$POOL/$1.qcow2" | grep -i 'virtual size')"
}
# Rocky를 실제 서버 모양으로 만든다. 클라우드 이미지에는 nftables도 firewalld도
# 없다. 둘을 설치하고 firewalld를 켠다. firewalld에는 wg 포트와 앱 포트 둘을
# 연다. 앱 포트를 firewalld가 열어 두어도 csa가 직통 경로를 막는지 보려는 것이다.
seed "$VM_A" "$IMG_UBUNTU" "true"
seed "$VM_B" "$IMG_ROCKY" "dnf -y install nftables firewalld >/dev/null 2>&1; firewall-offline-cmd --add-port=$PORT/udp --add-port=8080/tcp --add-port=9999/tcp >/dev/null 2>&1; systemctl enable --now firewalld >/dev/null 2>&1"

echo "== 가상 망"
cat > "$WORK/net.xml" <<XML
<network>
  <name>$NET</name>
  <forward mode='nat'/>
  <bridge name='cs-vmbr0' stp='on' delay='0'/>
  <ip address='10.98.0.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='10.98.0.100' end='10.98.0.200'/>
      <host mac='$MAC_A' name='$VM_A' ip='$IP_A'/>
      <host mac='$MAC_B' name='$VM_B' ip='$IP_B'/>
    </dhcp>
  </ip>
</network>
XML
virsh net-define "$WORK/net.xml" >/dev/null
virsh net-start "$NET" >/dev/null

echo "== VM 기동"
# 버스를 손으로 정하지 않는다. virtio로 바꾸었더니 Rocky가 직렬 포트로 한
# 바이트도 내지 않았다. 그 전에는 커널까지 갔다.
#
# 직렬 콘솔을 파일로 남긴다. libvirt가 아는 자리에만 남길 수 있다.
# --qemu-commandline으로 준 경로는 AppArmor 규칙을 만들어 주지 않아 qemu가 열지
# 못한다. SeaBIOS 로그를 그렇게 받으려다 도메인이 아예 뜨지 않았다.
# 콘솔 로그를 libvirt의 자리에 남긴다. 홈 디렉터리에 두면 AppArmor가 qemu의
# 쓰기를 막아 아무것도 남지 않는다.
CONSOLE_DIR=/var/log/libvirt/qemu
boot() { # 이름 mac
  mkdir -p "$CONSOLE_DIR"
  : > "$CONSOLE_DIR/$1-console.log"
  virt-install --name "$1" --memory 2048 --vcpus 2 --import \
    --disk "path=$POOL/$1.qcow2,format=qcow2" \
    --disk "path=$POOL/$1-seed.iso,device=cdrom" \
    --network "network=$NET,mac=$2" \
    --osinfo detect=on,require=off \
    --serial "file,path=$CONSOLE_DIR/$1-console.log" \
    --graphics none --noautoconsole >/dev/null
}
boot "$VM_A" "$MAC_A"
boot "$VM_B" "$MAC_B"

wait_ssh() { # 이름 주소
  for i in $(seq 90); do
    if $SSH "root@$2" true 2>/dev/null; then
      echo "  $1에 붙었습니다. $((i * 2))초 걸렸습니다."
      return 0
    fi
    if [ $((i % 15)) = 0 ]; then
      echo "  $1을 기다립니다. $((i * 2))초 지났습니다. 지금 상태: $(virsh domstate "$1" 2>&1)"
    fi
    sleep 2
  done
  diagnose "$1" "$2"
  return 1
}

# diagnose는 붙지 못했을 때 볼 것을 모아 찍는다. 무엇을 볼지 없어서 두 번
# 헤맸다. 다른 VM의 로그도 함께 찍는다. 둘 다 비어 있으면 그 VM의 문제가
# 아니라 로그를 남기는 방법의 문제다.
diagnose() { # 이름 주소
  echo "  $1($2)에 붙지 못했습니다." >&2
  echo "  --- 도메인 상태 ---" >&2
  virsh list --all >&2 || true
  echo "  --- DHCP가 준 주소 ---" >&2
  virsh net-dhcp-leases "$NET" >&2 || true
  for vm in "$VM_A" "$VM_B"; do
    echo "  --- $vm 콘솔 ($(wc -c < "$CONSOLE_DIR/$vm-console.log" 2>/dev/null || echo 0)바이트) ---" >&2
    tail -30 "$CONSOLE_DIR/$vm-console.log" 2>/dev/null >&2 || echo "    로그가 없습니다" >&2
  done
  # 손님이 실제로 돌고 있는지 본다. 멈춰 있으면 이 값이 늘지 않는다.
  t1=$(virsh domstats "$1" --cpu-total 2>/dev/null | sed -n 's/.*cpu.time=\([0-9]*\).*/\1/p')
  sleep 2
  t2=$(virsh domstats "$1" --cpu-total 2>/dev/null | sed -n 's/.*cpu.time=\([0-9]*\).*/\1/p')
  echo "  --- 2초 동안 쓴 CPU 시간: $(( (${t2:-0} - ${t1:-0}) / 1000000 ))밀리초 ---" >&2
  echo "  --- $1의 디스크와 직렬 포트 ---" >&2
  virsh dumpxml "$1" 2>/dev/null | sed -n "/<disk/,/<\/disk>/p;/<serial/,/<\/serial>/p" >&2 || true
  echo "  --- libvirt가 남긴 $1 로그 마지막 30줄 ---" >&2
  tail -30 "/var/log/libvirt/qemu/$1.log" 2>/dev/null >&2 || echo "    로그가 없습니다" >&2
  echo "  --- $1 디스크 ---" >&2
  qemu-img info "$POOL/$1.qcow2" >&2 2>&1 || true
}
echo "  붙기를 기다립니다. 두 머신이 뜨는 데 1분쯤 걸립니다."
wait_ssh "$VM_A" "$IP_A"
wait_ssh "$VM_B" "$IP_B"
# sshd는 cloud-init이 준비 명령을 끝내기 전에 뜬다. 패키지 설치가 끝날 때까지 기다린다.
echo "  cloud-init이 준비를 마치기를 기다립니다. Rocky는 패키지를 둘 설치합니다."
for ip in "$IP_A" "$IP_B"; do
  $SSH "root@$ip" 'cloud-init status --wait >/dev/null 2>&1 || true'
done

echo "== 키와 설정"
PUB_A=$("$CSA" genkey -o "$WORK/a.key" | sed -n 's/^공개키: //p')
PUB_B=$("$CSA" genkey -o "$WORK/b.key" | sed -n 's/^공개키: //p')

peers_toml() {
  cat <<TOML
[[peer]]
peer-id    = "vm-a"
public-key = "$PUB_A"
tunnel-ip  = "$WG_A"
endpoints  = ["$IP_A:$PORT"]
services   = [{ app = "$APP_A", port = 8080 }]

[[peer]]
peer-id    = "vm-b"
public-key = "$PUB_B"
tunnel-ip  = "$WG_B"
endpoints  = ["$IP_B:$PORT"]
services   = [{ app = "$APP_B", port = 8080 }]
TOML
}
side() { # 로컬디렉터리 peer-id 내앱 상대 상대앱
  mkdir -p "$WORK/$1"
  peers_toml > "$WORK/$1/peers.toml"
  cat > "$WORK/$1/csa.toml" <<TOML
peer-id     = "$2"
private-key = "/etc/callsignet/private.key"
tunnel-cidr = "$CIDR"
listen-port = $PORT

[tun]
name = "cs0"
mtu  = 1420
TOML
  cat > "$WORK/$1/policy.toml" <<TOML
outbound = ["$4/$5"]

[[inbound]]
app   = "$3"
allow = ["$4"]
TOML
}
side a vm-a "$APP_A" vm-b "$APP_B"
side b vm-b "$APP_B" vm-a "$APP_A"

push() { # 주소 로컬디렉터리 키파일
  $SSH "root@$1" "mkdir -p /etc/callsignet"
  $SCP "$CSA" "root@$1:/usr/local/bin/csa" >/dev/null
  $SCP "$WORK/$2/csa.toml" "$WORK/$2/peers.toml" "$WORK/$2/policy.toml" \
       "root@$1:/etc/callsignet/" >/dev/null
  $SCP "$WORK/$3" "root@$1:/etc/callsignet/private.key" >/dev/null
  $SSH "root@$1" "chmod 600 /etc/callsignet/private.key && csa check -c /etc/callsignet"
}
push "$IP_A" a a.key
push "$IP_B" b b.key

echo "== 기동 전 리졸버"
# csa는 이 파일을 건드리지 않아야 한다. 기동 전의 내용을 적어 두고 뒤에 견준다.
for pair in "$IP_A A(Ubuntu)" "$IP_B B(Rocky)"; do
  set -- $pair
  printf '  %-12s %s\n' "$2" "$($SSH "root@$1" 'ls -l /etc/resolv.conf | sed "s/.*resolv.conf/resolv.conf/"')"
  $SSH "root@$1" 'cat /etc/resolv.conf | grep -v "^#" | grep . | head -3' | sed 's/^/               /'
done
RESOLV_A0=$($SSH "root@$IP_A" 'cat /etc/resolv.conf')
RESOLV_B0=$($SSH "root@$IP_B" 'cat /etc/resolv.conf')
# 역경로 검사를 엄격하게 둔다. 받는 쪽 표가 출발지를 라우팅 뒤에 바꾸므로 이
# 검사에 걸리지 않아야 한다. Ubuntu의 기본은 느슨(2)이다.
for h in "$IP_A" "$IP_B"; do
  $SSH "root@$h" 'sysctl -q -w net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1'
done

echo
echo "== csa 기동"
$SSH "root@$IP_A" 'nohup csa run -c /etc/callsignet > /var/log/csa.log 2>&1 & sleep 1'
$SSH "root@$IP_B" 'nohup csa run -c /etc/callsignet > /var/log/csa.log 2>&1 & sleep 1'
sleep 8
for pair in "$IP_A A(Ubuntu)" "$IP_B B(Rocky)"; do
  set -- $pair
  echo "  --- $2의 csa 로그 ---"
  $SSH "root@$1" 'cat /var/log/csa.log' 2>/dev/null | sed 's/^/    /' || echo "    로그가 없습니다"
done

VM_OK=1
# csa가 죽어 있으면 그 뒤의 검사는 뜻이 없다. 여기서 멈춘다.
for pair in "$IP_A A(Ubuntu)" "$IP_B B(Rocky)"; do
  set -- $pair
  if ! $SSH "root@$1" 'pgrep -x csa >/dev/null'; then
    echo "  $2에서 csa가 죽었습니다. 위 로그를 보십시오."
    echo "  --- $2의 nft와 PATH ---"
    $SSH "root@$1" 'ls -l /usr/sbin/nft 2>&1; echo "PATH=$PATH"; rpm -q nftables 2>/dev/null || dpkg -l nftables 2>/dev/null | tail -1' | sed 's/^/    /'
    exit 1
  fi
done
# SAID는 기록에 남길 검사 결과다. LINES는 bash가 터미널 높이로 쓰므로
# 그 이름을 쓰면 값이 덮어써진다.
SAID=""
say() { # ok/틀림 설명
  if [ "$1" = ok ]; then printf '  ok    %s\n' "$2"; else printf '  틀림  %s\n' "$2"; VM_OK=0; fi
  SAID="$SAID| $1 | $2 |
"
}
# on_a와 on_b는 출력을 얻을 때 쓴다. 실패해도 스크립트가 멈추지 않도록 결과를
# 삼킨다. 성공했는지가 곧 검사인 자리에는 쓰면 안 된다. 늘 참이 된다.
on_a() { $SSH "root@$IP_A" "$1" 2>/dev/null || true; }
on_b() { $SSH "root@$IP_B" "$1" 2>/dev/null || true; }
# try_a는 성공했는지가 곧 검사인 자리에 쓴다.
try_a() { $SSH "root@$IP_A" "$1" >/dev/null 2>&1; }
# log_has는 그 머신의 csa 로그에 문구가 나타나기를 5초까지 기다린다. 로그를
# 가져와 이 호스트에서 견준다. 문구를 저쪽 셸에 넘겨 저쪽 grep으로 보면 로케일과
# 따옴표가 끼어든다. 실제로 로그에 있는 줄을 저쪽 grep이 찾지 못한 일이 있었다.
# 한 번만 보지 않는 까닭은 SSH가 한 번 어긋나거나 로그가 늦게 쓰일 수 있기 때문이다.
log_has() { # 주소 문구
  for _ in $(seq 10); do
    if $SSH "root@$1" 'cat /var/log/csa.log' 2>/dev/null | grep -q -- "$2"; then return 0; fi
    sleep 0.5
  done
  return 1
}

echo
echo "== 건드리지 않는 것"
if [ "$(on_a 'cat /etc/resolv.conf')" = "$RESOLV_A0" ] && [ "$(on_b 'cat /etc/resolv.conf')" = "$RESOLV_B0" ]; then
  say ok "csa가 두 머신의 /etc/resolv.conf를 건드리지 않는다"
else say 틀림 "csa가 /etc/resolv.conf를 고쳤다"; fi
if ! on_a "resolvectl status cs0" | grep -qi "DNS Domain\|in-addr.arpa"; then
  say ok "csa가 systemd-resolved에 아무것도 등록하지 않는다"
else say 틀림 "systemd-resolved에 등록한 것이 있다"; on_a "resolvectl status cs0" | sed 's/^/        /'; fi
if ! on_a 'grep -q "이름 해석" /var/log/csa.log && echo yes' | grep -q yes; then
  say ok "csa가 이름 해석을 하지 않는다"
else say 틀림 "csa가 이름 해석을 한다고 적었다"; fi

echo
echo "== 터널"
if try_a "ping -c 3 -W 2 -I cs0 $WG_B"; then
  say ok "진짜 머신 둘 사이에 터널이 선다"
else say 틀림 "터널이 서지 않는다"; on_a 'tail -20 /var/log/csa.log' | sed 's/^/        /'; fi

echo
echo "== 실제 IP로 부른 연결"
# 서버는 B의 실제 IP 하나에만 듣는다. A의 앱은 B의 실제 IP로 부른다. A의 표가
# 그 연결을 터널로 돌리고 B의 표가 목적지를 실제 IP로 되돌려야 서버가 받는다.
$SSH "root@$IP_B" "nohup python3 -c \"
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$IP_B', 8080)); s.listen(1)
c, peer = s.accept(); c.sendall(b'pong:' + c.recv(64)); print(peer[0], flush=True); c.close()
\" > /var/log/serve.out 2>&1 &
sleep 1"
got=$(on_a "timeout 5 bash -c 'exec 3<>/dev/tcp/$IP_B/8080; printf \"ping\\n\" >&3; head -1 <&3'")
if [ "$got" = "pong:ping" ]; then
  say ok "진짜 NIC에서도 실제 IP로 부른 TCP가 터널로 간다"
else say 틀림 "실제 IP로 TCP가 서지 않는다: ${got:-없음}"; on_a 'tail -10 /var/log/csa.log' | sed 's/^/        /'; fi
if log_has "$IP_B" "들어온 연결을 받았습니다.*상대 vm-a.*:8080"; then
  say ok "받는 쪽 csa의 기록에 peer-id가 남는다. 터널로 왔다"
else say 틀림 "받는 쪽 csa의 기록에 그 연결이 없다"; on_b 'grep "들어온 연결" /var/log/csa.log' | sed 's/^/        /'; fi
if [ "$(on_b 'head -1 /var/log/serve.out')" = "$IP_A" ]; then
  say ok "실제 IP에 바인딩한 서버가 받고 상대를 보낸 쪽의 실제 IP로 본다. 엄격한 역경로 검사에서도 그렇다"
else say 틀림 "서버가 보는 상대 주소가 다르다: $(on_b 'head -1 /var/log/serve.out')"; fi
if [ "$(on_a 'csa status -c /etc/callsignet -json' | sed -n 's/.*"nat-steered":\([0-9]*\).*/\1/p')" -gt 0 ] 2>/dev/null; then
  say ok "csa status가 터널로 돌린 연결을 센다"
else say 틀림 "돌린 연결을 세지 않는다"; fi

echo
echo "== 직통 경로"
# 이 호스트가 csa 없는 머신 노릇을 한다. 가상 망의 브리지로 두 VM에 바로 닿는다.
$SSH "root@$IP_B" "nohup python3 -c \"
import socket, threading
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port)); s.listen(8)
    while True:
        c, _ = s.accept(); c.sendall(b'here\\n'); c.close()
threading.Thread(target=serve, args=(8080,), daemon=True).start()
serve(9999)
\" >/dev/null 2>&1 &
sleep 1"
knock() { timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2; head -1 <&3" 2>/dev/null || true; }
if log_has "$IP_B" "직통 경로를 닫았습니다"; then
  say ok "Rocky에서 csa가 직통 경로를 닫았다"
else say 틀림 "Rocky에서 닫지 못했다"; on_b 'grep "직통 경로" /var/log/csa.log' | sed 's/^/        /'; fi
if on_b 'systemctl is-active firewalld' | grep -q '^active'; then
  say ok "firewalld가 함께 돌고 있다"
else say 틀림 "firewalld가 돌지 않는다. 함께 도는 것을 보지 못했다"; fi
if on_b 'nft list table inet callsignet >/dev/null 2>&1 && echo yes' | grep -q yes; then
  say ok "firewalld의 표 곁에 csa의 직통 경로 표가 있다"
else say 틀림 "csa의 표가 없다"; on_b 'nft list tables' | sed 's/^/        /'; fi
if on_b 'nft list table ip callsignet-nat >/dev/null 2>&1 && echo yes' | grep -q yes; then
  say ok "주소 바꾸기 표도 곁에 있다"
else say 틀림 "주소 바꾸기 표가 없다"; on_b 'nft list tables' | sed 's/^/        /'; fi
if [ -z "$(knock "$IP_B" 8080)" ]; then
  say ok "firewalld가 8080을 열어 두어도 csa가 직통 경로를 막는다"
else say 틀림 "실제 IP로 서비스 포트에 붙었다"; fi
if [ "$(knock "$IP_B" 9999)" = "here" ]; then
  say ok "peers.toml에 없는 포트는 그대로 열려 있다"
else say 틀림 "적지 않은 포트까지 막았다. firewalld가 막았을 수도 있다"; fi
on_b 'pkill -f "serve(9999)"' >/dev/null

echo
echo "== 되돌리기"
on_a 'pkill -TERM csa'; on_b 'pkill -TERM csa'
sleep 3
if [ -z "$(on_a 'ip link show cs0 2>/dev/null')" ]; then
  say ok "A에서 인터페이스가 사라졌다"
else say 틀림 "A에 인터페이스가 남았다"; fi
if ! on_b 'nft list table ip callsignet-nat >/dev/null 2>&1 && echo yes' | grep -q yes &&
   ! on_b 'nft list table inet callsignet >/dev/null 2>&1 && echo yes' | grep -q yes; then
  say ok "B에서 표 둘을 지웠다"
else say 틀림 "B에 표가 남았다"; on_b 'nft list tables' | sed 's/^/        /'; fi
if [ "$(on_b 'cat /etc/resolv.conf')" = "$RESOLV_B0" ]; then
  say ok "멈춘 뒤에도 B의 /etc/resolv.conf는 그대로다"
else say 틀림 "B의 /etc/resolv.conf가 달라졌다"; fi

echo
if [ "$VM_OK" != 1 ]; then
  echo "어긋난 것이 있습니다. 남은 것을 봅니다."
  for pair in "$IP_A A(Ubuntu)" "$IP_B B(Rocky)"; do
    set -- $pair
    echo "--- $2의 csa 로그 ---"
    $SSH "root@$1" 'tail -30 /var/log/csa.log' 2>/dev/null | sed 's/^/    /' || true
    echo "--- $2의 표 ---"
    $SSH "root@$1" 'nft list table ip callsignet-nat; nft list table inet callsignet' 2>/dev/null | sed 's/^/    /' || true
  done
  exit 1
fi
echo "확인됨. 실제 머신 둘에서 앱이 실제 IP로 부른 연결이 터널로 간다."

# 무엇을 언제 확인했는지 남긴다. 이 시험은 CI에서 돌지 않으므로 기록이 없으면
# 발행할 때 무엇을 확인했는지 보일 방법이 없다.
mkdir -p "$RESULTS"
own "$RESULTS"
REPORT="$RESULTS/vm-$(date -u +%Y%m%dT%H%M%SZ).md"
{
  echo "# VM 시험 ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo
  echo "커밋 $(git -C "$REPO" rev-parse --short HEAD), csa의 판 $("$CSA" version)"
  echo "A는 Ubuntu 24.04, B는 Rocky 9다."
  echo
  echo "| 결과 | 확인한 것 |"
  echo "|---|---|"
  printf '%s' "$SAID"
} > "$REPORT"
own "$REPORT"
echo
echo "기록: ${REPORT#$REPO/}"
