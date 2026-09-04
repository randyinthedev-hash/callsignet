#!/usr/bin/env bash
# 실제 VM 둘에서 csa를 돌려 리졸버 자리 차지하기를 확인한다.
#
# 네임스페이스 하네스가 밟지 못하는 것을 여기서 밟는다. Ubuntu에는
# systemd-resolved가 돌고 Rocky에는 NetworkManager가 돈다. 두 머신에서 csa가
# 어느 갈래를 타고 이름이 실제로 풀리는지 본다. 터널도 진짜 머신 둘 사이에서
# 처음으로 확인한다.
set -euo pipefail

NET=cs-vmnet
VM_A=cs-vm-a          # Ubuntu 24.04. systemd-resolved가 돈다
VM_B=cs-vm-b          # Rocky 9. NetworkManager가 돈다
MAC_A=52:54:00:c5:00:0a
MAC_B=52:54:00:c5:00:0b
IP_A=10.98.0.10       # 언더레이
IP_B=10.98.0.30
WG_A=10.99.0.1        # 터널
WG_B=10.99.0.2
CIDR=10.99.0.0/24
PORT=51820
DOMAIN=cs.vm.internal
APP_A=billing
APP_B=report

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CSA="${CSA:-$REPO/csa-static}"
WORK="$HERE/_work"
POOL=/var/lib/libvirt/images
IMG_UBUNTU="$POOL/cs-base-ubuntu.qcow2"
IMG_ROCKY="$POOL/cs-base-rocky.qcow2"
URL_UBUNTU=https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img
URL_ROCKY=https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2

if [ "$(id -u)" -ne 0 ]; then echo "root가 필요합니다: sudo $0" >&2; exit 1; fi
if [ ! -x "$CSA" ]; then
  echo "csa를 정적으로 먼저 만드십시오: make build-static" >&2
  echo "Rocky는 Ubuntu보다 glibc가 낮아 동적으로 링크한 것은 돌지 않습니다." >&2
  exit 1
fi
if ldd "$CSA" >/dev/null 2>&1; then
  echo "$CSA가 동적으로 링크되어 있습니다. make build-static으로 다시 만드십시오." >&2
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
# Rocky는 firewalld가 wg 포트를 막으므로 끈다. 이 시험이 볼 것은 리졸버다.
seed "$VM_A" "$IMG_UBUNTU" "true"
seed "$VM_B" "$IMG_ROCKY" "systemctl disable --now firewalld 2>/dev/null || true"

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
# 버스와 장치 모델을 손으로 정한다. 이 머신에 osinfo-db가 없어 virt-install이
# generic으로 떨어지고, 그러면 디스크를 virtio가 아닌 버스에 붙인다. Rocky
# 클라우드 이미지의 initramfs에는 그 버스의 드라이버가 없어 루트를 찾지 못한다.
# 씨앗 ISO는 기본 버스에 둔다. cloud-init이 사용자 공간에서 읽으므로 드라이버가
# 이미 있다.
#
# 직렬 콘솔을 파일로 남긴다. 붙지 못했을 때 부팅이 어디서 멈췄는지 보려는 것이다.
# 콘솔 로그를 libvirt의 자리에 남긴다. 홈 디렉터리에 두면 AppArmor가 qemu의
# 쓰기를 막아 아무것도 남지 않는다.
CONSOLE_DIR=/var/log/libvirt/qemu
boot() { # 이름 mac
  mkdir -p "$CONSOLE_DIR"
  : > "$CONSOLE_DIR/$1-console.log"
  virt-install --name "$1" --memory 2048 --vcpus 2 --import \
    --disk "path=$POOL/$1.qcow2,format=qcow2,bus=virtio" \
    --disk "path=$POOL/$1-seed.iso,device=cdrom" \
    --network "network=$NET,mac=$2,model=virtio" \
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
domain      = "$DOMAIN"
tunnel-cidr = "$CIDR"
listen-port = $PORT

[tun]
name = "cs0"
mtu  = 1420

[dns]
listen = "127.0.0.54:53"

[guard]
mode = "off"
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
for pair in "$IP_A A(Ubuntu)" "$IP_B B(Rocky)"; do
  set -- $pair
  printf '  %-12s %s\n' "$2" "$($SSH "root@$1" 'ls -l /etc/resolv.conf | sed "s/.*resolv.conf/resolv.conf/"')"
  $SSH "root@$1" 'cat /etc/resolv.conf | grep -v "^#" | grep . | head -3' | sed 's/^/               /'
done

echo
echo "== csa 기동"
$SSH "root@$IP_A" 'nohup csa run -c /etc/callsignet > /var/log/csa.log 2>&1 & sleep 1'
$SSH "root@$IP_B" 'nohup csa run -c /etc/callsignet > /var/log/csa.log 2>&1 & sleep 1'
sleep 5

VM_OK=1
say() { # ok/틀림 설명
  if [ "$1" = ok ]; then printf '  ok    %s\n' "$2"; else printf '  틀림  %s\n' "$2"; VM_OK=0; fi
}
on_a() { $SSH "root@$IP_A" "$1" 2>/dev/null || true; }
on_b() { $SSH "root@$IP_B" "$1" 2>/dev/null || true; }

echo
echo "== A(Ubuntu) 리졸버 갈래"
GOT=$(on_a 'sed -n "s/.*관리 주체는 \(.*\)입니다.*/\1/p" /var/log/csa.log | head -1')
if [ "$GOT" = "systemd-resolved" ]; then say ok "systemd-resolved 갈래를 탄다"
else say 틀림 "다른 갈래를 탔다: ${GOT:-없음}"; fi
if [ -n "$(on_a 'test -L /etc/resolv.conf && echo yes')" ]; then
  say ok "/etc/resolv.conf를 건드리지 않는다"
else say 틀림 "파일을 고쳤다"; fi
if on_a "resolvectl status cs0" | grep -q "$DOMAIN"; then
  say ok "cs0에 내부 도메인을 등록했다"
else say 틀림 "도메인을 등록하지 못했다"; on_a "resolvectl status cs0" | sed 's/^/        /'; fi
if on_a "resolvectl status cs0" | grep -q "99.10.in-addr.arpa"; then
  say ok "역방향 구역도 등록했다"
else say 틀림 "역방향 구역이 없다"; fi

echo
echo "== B(Rocky) 리졸버 갈래"
GOT_B=$(on_b 'sed -n "s/.*관리 주체는 \(.*\)입니다.*/\1/p" /var/log/csa.log | head -1')
echo "  csa가 판별한 관리 주체: ${GOT_B:-없음}"
if on_b 'head -3 /etc/resolv.conf' | grep -q "127.0.0.54"; then
  say ok "자기를 첫 줄에 넣었다"
else say 틀림 "파일을 가져가지 못했다"; on_b 'head -5 /etc/resolv.conf' | sed 's/^/        /'; fi

echo
echo "== 이름 해석"
if [ "$(on_a "getent hosts $APP_B.vm-b.$DOMAIN | awk '{print \$1}'")" = "$WG_B" ]; then
  say ok "A가 시스템 경로로 B의 서비스 이름을 푼다"
else say 틀림 "A에서 이름이 풀리지 않는다: $(on_a "getent hosts $APP_B.vm-b.$DOMAIN")"; fi
if [ "$(on_b "getent hosts $APP_A.vm-a.$DOMAIN | awk '{print \$1}'")" = "$WG_A" ]; then
  say ok "B가 시스템 경로로 A의 서비스 이름을 푼다"
else say 틀림 "B에서 이름이 풀리지 않는다: $(on_b "getent hosts $APP_A.vm-a.$DOMAIN")"; fi
if on_a "getent hosts $WG_B" | grep -q "vm-b.$DOMAIN"; then
  say ok "A가 역방향으로 B의 머신 이름을 얻는다"
else say 틀림 "역방향이 풀리지 않는다: $(on_a "getent hosts $WG_B")"; fi

echo
echo "== 터널"
if on_a "ping -c 3 -W 2 -I cs0 $WG_B" >/dev/null 2>&1; then
  say ok "진짜 머신 둘 사이에 터널이 선다"
else say 틀림 "터널이 서지 않는다"; on_a 'tail -20 /var/log/csa.log' | sed 's/^/        /'; fi
if on_a "ping -c 2 -W 2 $APP_B.vm-b.$DOMAIN" >/dev/null 2>&1; then
  say ok "이름으로 통신한다"
else say 틀림 "이름으로는 통하지 않는다"; fi

echo
echo "== B의 파일이 남아 있나"
echo "  30초 기다립니다. NetworkManager가 되돌리는지 봅니다."
sleep 30
if on_b 'head -3 /etc/resolv.conf' | grep -q "127.0.0.54"; then
  say ok "NetworkManager가 되돌리지 않았다"
else say 틀림 "NetworkManager가 csa의 줄을 지웠다"; on_b 'head -5 /etc/resolv.conf' | sed 's/^/        /'; fi

echo
echo "== 되돌리기"
on_a 'pkill -TERM csa'; on_b 'pkill -TERM csa'
sleep 3
if ! on_a "resolvectl status cs0" | grep -q "$DOMAIN"; then
  say ok "A에서 인터페이스와 함께 설정이 사라졌다"
else say 틀림 "A에 설정이 남았다"; fi
if ! on_b 'head -3 /etc/resolv.conf' | grep -q "127.0.0.54"; then
  say ok "B에서 원래 파일로 되돌렸다"
else say 틀림 "B에 csa의 줄이 남았다"; fi

echo
[ "$VM_OK" = 1 ] || { echo "어긋난 것이 있습니다."; exit 1; }
echo "확인됨. 실제 머신 둘에서 두 갈래가 모두 돈다."
