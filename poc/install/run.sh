#!/usr/bin/env bash
# 깨끗한 VM에서 INSTALL.md대로 csa를 설치하고, 띄우고, 다음 판으로 올렸다가,
# 앞 판으로 되돌리고, 뜨지 못하는 판으로 올리면 스스로 되돌리는지, 지우면
# 깨끗이 지워지는지 본다.
#
# VM 둘에서 같은 것을 따로 밟는다. Ubuntu 24.04와 Rocky 9다. Rocky는 SELinux가
# 켜져 있어 /opt 아래의 실행 파일을 systemd가 띄우는 것이 막힐 수 있다. 그것을
# 여기서 본다. 각 VM은 혼자 돈다. 상대는 있지만 닿지 않는다. 설치 절차가 보는
# 것은 터널이 서는지가 아니라 csa가 뜨고 답하고 판이 바뀌는지다.
#
# 판 둘을 같은 코드로 만든다. 하나는 이 리포의 판이고 다른 하나는 -X로 판 이름만
# 바꾼 것이다. 올리기와 되돌리기가 보는 것은 판 이름과 링크와 서비스이지
# 코드의 차이가 아니다.
set -euo pipefail

NET=cs-instnet
VM_A=cs-inst-a        # Ubuntu 24.04
VM_B=cs-inst-b        # Rocky 9
MAC_A=52:54:00:c5:01:0a
MAC_B=52:54:00:c5:01:0b
IP_A=10.97.0.10
IP_B=10.97.0.30
PORT=51820
DOMAIN=cs.inst.internal

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$HERE/_work"
POOL=/var/lib/libvirt/images
IMG_UBUNTU="$POOL/cs-base-ubuntu.qcow2"
IMG_ROCKY="$POOL/cs-base-rocky.qcow2"
URL_UBUNTU=https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img
URL_ROCKY=https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2

. "$HERE/../lib.sh"
RESULTS="$REPO/results"

if [ "$(id -u)" -ne 0 ]; then echo "root가 필요합니다: sudo $0" >&2; exit 1; fi

KEEP="${KEEP:-0}"
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

echo "== 묶음 둘"
GO=$(find_go)
[ -n "$GO" ] || { echo "go를 찾지 못했습니다. 자리를 주십시오: sudo GO=/path/to/go $0" >&2; exit 1; }
# 같은 코드로 판 둘을 만든다. 둘째는 판 이름만 다르다.
( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -trimpath -ldflags "-w" -o "$WORK/csa-a" ./cmd/csa )
VER_A=$("$WORK/csa-a" version)
VER_B="$VER_A-next"
( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -trimpath -ldflags "-w -X main.Version=$VER_B" -o "$WORK/csa-b" ./cmd/csa )
mkdir -p "$WORK/a" "$WORK/b"
"$REPO/dist/pack.sh" "$WORK/csa-a" amd64 "$WORK/a" >/dev/null
"$REPO/dist/pack.sh" "$WORK/csa-b" amd64 "$WORK/b" >/dev/null
( cd "$WORK/a" && sha256sum csa-linux-amd64.tar.gz > sha256sum.txt )
( cd "$WORK/b" && sha256sum csa-linux-amd64.tar.gz > sha256sum.txt )
own "$WORK"
echo "  판 $VER_A 과 판 $VER_B 을 만들었습니다."

echo "== 바탕 이미지"
fetch() { # 주소 파일
  if [ -f "$2" ]; then echo "  이미 있습니다: $(basename "$2")"; return; fi
  echo "  받습니다: $(basename "$2")"
  curl -fsSL -o "$2.part" "$1" && mv "$2.part" "$2"
}
fetch "$URL_UBUNTU" "$IMG_UBUNTU"
fetch "$URL_ROCKY" "$IMG_ROCKY"

echo "== 열쇠와 씨앗"
ssh-keygen -q -t ed25519 -N "" -f "$WORK/id" -C csn-inst
PUB=$(cat "$WORK/id.pub")
SSH="ssh -q -i $WORK/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
SCP="scp -q -i $WORK/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

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
  qemu-img create -q -f qcow2 -F qcow2 -b "$2" "$POOL/$1.qcow2"
}
# 깨끗한 머신이다. Rocky의 클라우드 이미지에는 nftables가 없으므로 INSTALL.md의
# 준비물대로 그것만 설치한다.
seed "$VM_A" "$IMG_UBUNTU" "true"
seed "$VM_B" "$IMG_ROCKY" "dnf -y install nftables >/dev/null 2>&1"

echo "== 가상 망"
cat > "$WORK/net.xml" <<XML
<network>
  <name>$NET</name>
  <forward mode='nat'/>
  <bridge name='cs-inbr0' stp='on' delay='0'/>
  <ip address='10.97.0.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='10.97.0.100' end='10.97.0.200'/>
      <host mac='$MAC_A' name='$VM_A' ip='$IP_A'/>
      <host mac='$MAC_B' name='$VM_B' ip='$IP_B'/>
    </dhcp>
  </ip>
</network>
XML
virsh net-define "$WORK/net.xml" >/dev/null
virsh net-start "$NET" >/dev/null

echo "== VM 기동"
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
    sleep 2
  done
  echo "  $1($2)에 붙지 못했습니다." >&2
  tail -30 "$CONSOLE_DIR/$1-console.log" 2>/dev/null >&2 || true
  return 1
}
echo "  붙기를 기다립니다."
wait_ssh "$VM_A" "$IP_A"
wait_ssh "$VM_B" "$IP_B"
echo "  cloud-init이 준비를 마치기를 기다립니다."
for ip in "$IP_A" "$IP_B"; do
  $SSH "root@$ip" 'cloud-init status --wait >/dev/null 2>&1 || true'
done

# 설정 한 벌이다. 이 머신 자신과 닿지 않는 상대 하나다. 상대의 키는 여기서
# 만든 아무 키다.
echo "== 설정"
PUB_FAR=$("$WORK/csa-a" genkey -o "$WORK/far.key" | sed -n 's/^공개키: //p')
config() { # 로컬디렉터리 peer-id 터널IP 자기공개키
  mkdir -p "$WORK/$1"
  cat > "$WORK/$1/csa.toml" <<TOML
peer-id     = "$2"
private-key = "/etc/callsignet/private.key"
domain      = "$DOMAIN"
tunnel-cidr = "10.96.0.0/24"
listen-port = $PORT

[tun]
name = "cs0"
mtu  = 1420

[dns]
listen = "127.0.53.1:53"
TOML
  cat > "$WORK/$1/peers.toml" <<TOML
[[peer]]
peer-id    = "$2"
public-key = "$4"
tunnel-ip  = "$3"
endpoints  = ["$3:$PORT"]
services   = [{ app = "billing", port = 8080 }]

[[peer]]
peer-id    = "far"
public-key = "$PUB_FAR"
tunnel-ip  = "10.96.0.99"
endpoints  = ["10.97.0.99:$PORT"]
services   = [{ app = "report", port = 8080 }]
TOML
  cat > "$WORK/$1/policy.toml" <<TOML
outbound = ["far/report"]

[[inbound]]
app   = "billing"
allow = ["far"]
TOML
}

ALL_OK=1
SAID=""
say() { # ok/틀림 머신 설명
  if [ "$1" = ok ]; then printf '  ok    %s\n' "$3"; else printf '  틀림  %s\n' "$3"; ALL_OK=0; fi
  SAID="$SAID| $1 | $2 | $3 |
"
}

# 한 머신에서 INSTALL.md의 절차를 처음부터 끝까지 밟는다.
#
# 묶음은 일반 사용자가 홈에서 풀고 설치는 root가 한다. 실제로 그렇게 하는 사람이
# 많고, 그때 설치된 파일의 임자가 그 사용자로 남으면 root로 도는 실행 파일을
# 그 사용자가 고칠 수 있다.
#
# 잘못된 판을 여럿 만든다. 실행 파일 자리에 판만 말하고 나머지는 지금 판의
# csa에 넘기는 스크립트를 둔 것이다.
#   flaky    /etc/callsignet/no-check 가 있으면 check가 거절하고,
#            /etc/callsignet/no-run 이 있으면 run이 바로 죽는다
#   nospawn  해석기가 /home 아래에 있다. 서비스 파일이 홈을 숨기므로 systemd가
#            띄우지조차 못한다. systemctl restart 자체가 실패하는 자리다
#   lock     run이 /opt/callsignet 을 잠그고 죽는다. 돌아오는 것마저 막히는
#            자리다. 그때 스크립트가 「반쯤」이라고 말하는지 본다
#   badname  version이 빈 값이나 .. 이나 슬래시가 든 값을 찍는다
#   unitdiff 진짜 csa인데 csa.service가 다르다. 서비스 파일을 쓰지 못하게
#            잠가 두고 올리면 링크를 옮긴 뒤에 실패하는 자리가 된다
walk() { # 이름 주소 peer-id 터널IP
  local name=$1 ip=$2 pid=$3 tip=$4
  local run="$SSH root@$ip"
  local A="/opt/callsignet/versions/$VER_A/bin/csa"
  echo
  echo "== $name"

  $SSH "root@$ip" 'useradd -m inst 2>/dev/null || true; install -d -o inst -g inst /home/inst/a /home/inst/b'
  $SCP "$WORK/a/csa-linux-amd64.tar.gz" "$WORK/a/sha256sum.txt" "root@$ip:/home/inst/a/" >/dev/null
  $SCP "$WORK/b/csa-linux-amd64.tar.gz" "$WORK/b/sha256sum.txt" "root@$ip:/home/inst/b/" >/dev/null
  $run 'chown -R inst:inst /home/inst/a /home/inst/b'

  # 1. 일반 사용자가 묶음을 확인하고 푼다.
  if $run 'su - inst -c "cd ~/a && sha256sum -c --ignore-missing sha256sum.txt >/dev/null && tar -xzf csa-linux-amd64.tar.gz && cd ~/b && sha256sum -c --ignore-missing sha256sum.txt >/dev/null && tar -xzf csa-linux-amd64.tar.gz"'; then
    say ok "$name" "일반 사용자가 푼 묶음의 체크섬이 맞고 풀린다"
  else
    say 틀림 "$name" "일반 사용자가 푼 묶음의 체크섬이 맞고 풀린다"; return
  fi

  # 2. 손으로 설치한 csa가 있으면 설치하지 않는다. v0.1.3까지는 묶음이 없어
  #    운영자가 실행 파일을 /usr/local/bin 에 직접 두고 서비스 파일도 직접 썼다.
  #    그것을 덮어쓰거나 지우면 안 된다. 둘을 심어 두고 설치를 시도한다.
  $run 'printf "손으로 둔 실행 파일\n" > /usr/local/bin/csa && chmod 755 /usr/local/bin/csa && printf "[Unit]\nDescription=손으로 쓴 서비스 파일\n" > /etc/systemd/system/csa.service && sha256sum /usr/local/bin/csa /etc/systemd/system/csa.service > /root/handmade.sum'
  if ! $run 'cd /home/inst/a/csa-linux-amd64 && ./install.sh install >/root/install-way.log 2>&1' \
     && $run 'grep -q "덮어쓰거나 지우지 않습니다" /root/install-way.log && sha256sum -c --quiet /root/handmade.sum && [ ! -e /opt/callsignet ]'; then
    say ok "$name" "손으로 둔 실행 파일과 서비스 파일이 있으면 아무것도 덮어쓰거나 지우지 않고 거절한다"
  else
    say 틀림 "$name" "손으로 둔 실행 파일과 서비스 파일이 있으면 아무것도 덮어쓰거나 지우지 않고 거절한다"
    $run 'cat /root/install-way.log; sha256sum -c /root/handmade.sum; ls -la /opt/callsignet 2>&1' | sed 's/^/        /'
  fi
  $run 'rm -f /usr/local/bin/csa /etc/systemd/system/csa.service'

  # 3. 처음 설치가 중간에 실패하면 만든 것을 치운다. 서비스 파일을 둘 자리를
  #    잠가 두면 링크를 만든 뒤에 실패한다. 치운 뒤에는 다시 install 할 수 있어야
  #    한다.
  $run 'chattr +i /etc/systemd/system'
  if ! $run 'cd /home/inst/a/csa-linux-amd64 && ./install.sh install >/root/install-fail.log 2>&1' \
     && $run 'grep -q "치웠습니다" /root/install-fail.log && [ ! -e /opt/callsignet ] && [ ! -e /usr/local/bin/csa ] && [ ! -e /etc/systemd/system/csa.service ]'; then
    say ok "$name" "처음 설치가 중간에 실패하면 만든 것을 치운다"
  else
    say 틀림 "$name" "처음 설치가 중간에 실패하면 만든 것을 치운다"
    $run 'cat /root/install-fail.log; ls -la /opt/callsignet /usr/local/bin/csa 2>&1' | sed 's/^/        /'
  fi
  $run 'chattr -i /etc/systemd/system'

  # 4. root가 처음 설치한다. 설정이 없으므로 서비스는 켜져 있되 뜨지 않는다.
  if $run 'cd /home/inst/a/csa-linux-amd64 && ./install.sh install >/root/install.log 2>&1'; then
    say ok "$name" "처음 설치가 끝난다"
  else
    say 틀림 "$name" "처음 설치가 끝난다"; $run 'cat /root/install.log' | sed 's/^/        /'; return
  fi
  if [ "$($run 'find /opt/callsignet \( ! -user root -o ! -group root \) | wc -l')" = "0" ]; then
    say ok "$name" "설치된 파일이 모두 root의 것이다"
  else
    say 틀림 "$name" "설치된 파일이 모두 root의 것이다"
    $run 'find /opt/callsignet \( ! -user root -o ! -group root \) -ls | head' | sed 's/^/        /'
  fi
  if $run '! su - inst -c "test -w /opt/callsignet/current/bin/csa" && ! su - inst -c "sh -c \"echo x >> /opt/callsignet/current/bin/csa\"" 2>/dev/null'; then
    say ok "$name" "묶음을 푼 일반 사용자가 설치된 실행 파일을 고치지 못한다"
  else
    say 틀림 "$name" "묶음을 푼 일반 사용자가 설치된 실행 파일을 고치지 못한다"
  fi
  if $run 'systemctl is-enabled csa >/dev/null 2>&1 && ! systemctl is-active csa >/dev/null 2>&1'; then
    say ok "$name" "서비스는 켜져 있고 설정이 없어 뜨지 않는다"
  else
    say 틀림 "$name" "서비스는 켜져 있고 설정이 없어 뜨지 않는다"
  fi
  if [ "$($run 'csa version')" = "$VER_A" ]; then
    say ok "$name" "/usr/local/bin/csa 가 판 $VER_A 이다"
  else
    say 틀림 "$name" "/usr/local/bin/csa 가 판 $VER_A 이다"
  fi

  # 3. 설정을 둔다. 문서의 명령 그대로다.
  local pub
  pub=$($run 'csa genkey -o /etc/callsignet/private.key' | sed -n 's/^공개키: //p')
  config "$name" "$pid" "$tip" "$pub"
  $SCP "$WORK/$name/csa.toml" "$WORK/$name/peers.toml" "$WORK/$name/policy.toml" "root@$ip:/etc/callsignet/" >/dev/null
  if $run 'install -d -m 700 /etc/callsignet/psk && csa check -c /etc/callsignet >/dev/null'; then
    say ok "$name" "설정을 두면 csa check가 지난다"
  else
    say 틀림 "$name" "설정을 두면 csa check가 지난다"; return
  fi

  # 4. 띄운다.
  answers() { $SSH "root@$ip" 'for i in $(seq 15); do csa status -c /etc/callsignet >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'; }
  cur() { $SSH "root@$ip" 'basename $(readlink -f /opt/callsignet/current)' 2>/dev/null; }
  prev() { $SSH "root@$ip" 'basename $(readlink -f /opt/callsignet/previous)' 2>/dev/null; }
  if $run 'systemctl start csa' && answers; then
    say ok "$name" "systemctl start 뒤 csa status가 답한다"
  else
    say 틀림 "$name" "systemctl start 뒤 csa status가 답한다"
    $run 'journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
    return
  fi
  if $run 'systemctl reload csa'; then
    say ok "$name" "systemctl reload가 통한다"
  else
    say 틀림 "$name" "systemctl reload가 통한다"
  fi

  # 5. 올린다.
  if $run 'cd /home/inst/b/csa-linux-amd64 && ./install.sh upgrade >/root/upgrade.log 2>&1' \
     && [ "$($run 'csa version')" = "$VER_B" ] && answers; then
    say ok "$name" "올리면 판이 $VER_B 이 되고 csa가 답한다"
  else
    say 틀림 "$name" "올리면 판이 $VER_B 이 되고 csa가 답한다"
    $run 'cat /root/upgrade.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi
  if [ "$(prev)" = "$VER_A" ]; then
    say ok "$name" "앞 판 링크가 $VER_A 을 가리킨다"
  else
    say 틀림 "$name" "앞 판 링크가 $VER_A 을 가리킨다"
  fi

  # 6. 되돌린다.
  if $run 'cd /home/inst/b/csa-linux-amd64 && ./install.sh rollback >/root/rollback.log 2>&1' \
     && [ "$($run 'csa version')" = "$VER_A" ] && answers; then
    say ok "$name" "되돌리면 판이 $VER_A 이 되고 csa가 답한다"
  else
    say 틀림 "$name" "되돌리면 판이 $VER_A 이 되고 csa가 답한다"
    $run 'cat /root/rollback.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi

  # 앞 판과 같은 이름의 판을 두다 실패해도 앞 판이 남는다. 앞 판의 디렉터리를
  # 잠가 두면 옆으로 밀어 두는 자리에서 실패한다. 지금 판 A, 앞 판 B다.
  $run "chattr +i /opt/callsignet/versions/$VER_B"
  if ! $run 'cd /home/inst/b/csa-linux-amd64 && ./install.sh upgrade >/root/prevdup.log 2>&1' \
     && $run 'grep -q "아무것도 바꾸지 않았습니다" /root/prevdup.log' \
     && [ "$(cur)" = "$VER_A" ] && [ "$(prev)" = "$VER_B" ] \
     && $run "[ -x /opt/callsignet/versions/$VER_B/bin/csa ] && [ \"\$(ls -A /opt/callsignet/versions | grep -c '^\\.')\" = 0 ]" && answers; then
    say ok "$name" "앞 판과 같은 이름의 판을 두다 실패해도 앞 판이 그대로 남는다"
  else
    say 틀림 "$name" "앞 판과 같은 이름의 판을 두다 실패해도 앞 판이 그대로 남는다"
    $run 'cat /root/prevdup.log; ls -la /opt/callsignet/versions' | sed 's/^/        /'
  fi
  $run "chattr -i /opt/callsignet/versions/$VER_B"

  # 잘못된 판을 만드는 도우미다. 이름과 스크립트 몸통을 받는다.
  fake() { # 이름 몸통
    $SSH "root@$ip" "rm -rf /root/$1 && cp -a /home/inst/b/csa-linux-amd64 /root/$1 && cat > /root/$1/bin/csa <<'EOF'
$2
EOF
chmod 755 /root/$1/bin/csa"
  }

  # 앞 판이라는 이름을 단 다른 묶음으로 올리다 실패해도 앞 판의 원본이 그대로
  # 남는다. 검사에 걸리는 것과 뜨지 못하는 것 둘 다다. 앞 판을 밀어 두고 새것을
  # 놓은 뒤에 실패하는 자리다. 밀어 둔 것을 지워 버리면 되돌릴 자리를 잃는다.
  local bsum
  bsum=$($run "sha256sum /opt/callsignet/versions/$VER_B/bin/csa | cut -d' ' -f1")
  fake asb-check "#!/bin/sh
case \"\$1\" in
  version) echo $VER_B ;;
  check) echo '일부러 거절합니다' >&2; exit 1 ;;
  *) exec $A \"\$@\" ;;
esac"
  fake asb-run "#!/bin/sh
case \"\$1\" in
  version) echo $VER_B ;;
  run) echo '일부러 죽습니다' >&2; exit 1 ;;
  *) exec $A \"\$@\" ;;
esac"
  if ! $run 'cd /root/asb-check && ./install.sh upgrade >/root/asb-check.log 2>&1' \
     && [ "$($run "sha256sum /opt/callsignet/versions/$VER_B/bin/csa | cut -d' ' -f1")" = "$bsum" ] \
     && [ "$(cur)" = "$VER_A" ] && [ "$(prev)" = "$VER_B" ] \
     && $run "[ \"\$(ls -A /opt/callsignet/versions | grep -c '^\\.')\" = 0 ]" && answers; then
    say ok "$name" "앞 판의 이름을 단 묶음이 검사에 걸리면 앞 판의 원본이 그대로 남는다"
  else
    say 틀림 "$name" "앞 판의 이름을 단 묶음이 검사에 걸리면 앞 판의 원본이 그대로 남는다"
    $run "cat /root/asb-check.log; ls -la /opt/callsignet/versions; sha256sum /opt/callsignet/versions/$VER_B/bin/csa" | sed 's/^/        /'
  fi
  if ! $run 'cd /root/asb-run && ./install.sh upgrade >/root/asb-run.log 2>&1' \
     && [ "$($run "sha256sum /opt/callsignet/versions/$VER_B/bin/csa | cut -d' ' -f1")" = "$bsum" ] \
     && [ "$(cur)" = "$VER_A" ] && [ "$(prev)" = "$VER_B" ] \
     && $run "[ \"\$(ls -A /opt/callsignet/versions | grep -c '^\\.')\" = 0 ]" && answers; then
    say ok "$name" "앞 판의 이름을 단 묶음이 뜨지 못하면 시도 전으로 돌아오고 앞 판의 원본이 그대로 남는다"
  else
    say 틀림 "$name" "앞 판의 이름을 단 묶음이 뜨지 못하면 시도 전으로 돌아오고 앞 판의 원본이 그대로 남는다"
    $run "cat /root/asb-run.log; ls -la /opt/callsignet/versions; sha256sum /opt/callsignet/versions/$VER_B/bin/csa; journalctl -u csa --no-pager | tail -10" | sed 's/^/        /'
  fi
  fake flaky "#!/bin/sh
case \"\$1\" in
  version) echo $VER_A-flaky ;;
  check) [ -e /etc/callsignet/no-check ] && { echo '일부러 거절합니다' >&2; exit 1; }; exec $A \"\$@\" ;;
  run) [ -e /etc/callsignet/no-run ] && { echo '일부러 죽습니다' >&2; exit 1; }; exec $A \"\$@\" ;;
  *) exec $A \"\$@\" ;;
esac"
  $run 'cp -L /bin/sh /home/inst/sh && chmod 755 /home/inst/sh'
  fake nospawn "#!/home/inst/sh
case \"\$1\" in
  version) echo $VER_A-nospawn ;;
  *) exec $A \"\$@\" ;;
esac"
  fake lock "#!/bin/sh
case \"\$1\" in
  version) echo $VER_A-lock ;;
  run) chattr +i /opt/callsignet; echo '일부러 잠그고 죽습니다' >&2; exit 1 ;;
  *) exec $A \"\$@\" ;;
esac"

  # 7. 떠서 바로 죽는 판으로 올린다. 올리기는 실패로 끝나야 하고, 끝난 뒤에는
  #    링크 둘 다 시도하기 전 그대로여야 한다. 지금 판 A, 앞 판 B다.
  $run 'touch /etc/callsignet/no-run'
  if ! $run 'cd /root/flaky && ./install.sh upgrade >/root/flaky1.log 2>&1' \
     && [ "$(cur)" = "$VER_A" ] && [ "$(prev)" = "$VER_B" ] && answers; then
    say ok "$name" "떠서 바로 죽는 판으로 올리면 링크 둘 다 시도 전 그대로 돌아오고 csa가 답한다"
  else
    say 틀림 "$name" "떠서 바로 죽는 판으로 올리면 링크 둘 다 시도 전 그대로 돌아오고 csa가 답한다"
    $run 'cat /root/flaky1.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi
  $run 'rm -f /etc/callsignet/no-run'

  # 8. systemd가 띄우지조차 못하는 판으로 올린다. systemctl restart가 실패하는
  #    자리다. 그래도 시도 전 그대로 돌아와야 한다.
  if ! $run 'cd /root/nospawn && ./install.sh upgrade >/root/nospawn.log 2>&1' \
     && [ "$(cur)" = "$VER_A" ] && [ "$(prev)" = "$VER_B" ] && answers; then
    say ok "$name" "다시 띄우기 자체가 실패해도 시도 전 그대로 돌아온다"
  else
    say 틀림 "$name" "다시 띄우기 자체가 실패해도 시도 전 그대로 돌아온다"
    $run 'cat /root/nospawn.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi

  # 9. 사전 검사에 걸리는 판. 두 번 시도해도 같은 까닭으로 막히고, 까닭을
  #    치우면 같은 묶음으로 올라간다.
  $run 'touch /etc/callsignet/no-check'
  if ! $run 'cd /root/flaky && ./install.sh upgrade >/root/flaky2.log 2>&1' \
     && ! $run 'cd /root/flaky && ./install.sh upgrade >/root/flaky3.log 2>&1' \
     && $run 'grep -q "받지 않습니다" /root/flaky3.log' \
     && [ "$(cur)" = "$VER_A" ] && answers; then
    say ok "$name" "사전 검사에 걸리면 아무것도 바꾸지 않고 같은 묶음으로 다시 시도할 수 있다"
  else
    say 틀림 "$name" "사전 검사에 걸리면 아무것도 바꾸지 않고 같은 묶음으로 다시 시도할 수 있다"
    $run 'cat /root/flaky2.log /root/flaky3.log' | sed 's/^/        /'
  fi
  $run 'rm -f /etc/callsignet/no-check'
  if $run 'cd /root/flaky && ./install.sh upgrade >/root/flaky4.log 2>&1' \
     && [ "$(cur)" = "$VER_A-flaky" ] && answers; then
    say ok "$name" "까닭을 치우면 같은 묶음으로 올라간다"
  else
    say 틀림 "$name" "까닭을 치우면 같은 묶음으로 올라간다"
    $run 'cat /root/flaky4.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi

  # 10. 앞 판이 지금 설정을 거절하면 되돌리기는 옮기기 전에 멈춘다. flaky에서
  #     B로 올린 뒤 no-check 를 두면 앞 판인 flaky가 거절한다.
  $run 'cd /home/inst/b/csa-linux-amd64 && ./install.sh upgrade >/root/upgrade2.log 2>&1' || true
  $run 'touch /etc/callsignet/no-check'
  if [ "$(cur)" = "$VER_B" ] && [ "$(prev)" = "$VER_A-flaky" ] \
     && ! $run 'cd /root/flaky && ./install.sh rollback >/root/rollback2.log 2>&1' \
     && $run 'grep -q "받지 않습니다" /root/rollback2.log' \
     && [ "$(cur)" = "$VER_B" ] && answers; then
    say ok "$name" "앞 판이 지금 설정을 거절하면 되돌리기가 옮기기 전에 멈춘다"
  else
    say 틀림 "$name" "앞 판이 지금 설정을 거절하면 되돌리기가 옮기기 전에 멈춘다"
    $run 'cat /root/upgrade2.log /root/rollback2.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi
  $run 'rm -f /etc/callsignet/no-check'

  # 11. 앞 판이 뜨지 못하면 되돌리기가 원래 판으로 돌아온다. 지금 판 B, 앞 판
  #     flaky에서 no-run 을 두고 되돌린다. 검사는 지나지만 뜨지 못한다.
  $run 'touch /etc/callsignet/no-run'
  if ! $run 'cd /root/flaky && ./install.sh rollback >/root/rollback3.log 2>&1' \
     && [ "$(cur)" = "$VER_B" ] && [ "$(prev)" = "$VER_A-flaky" ] && answers; then
    say ok "$name" "앞 판이 뜨지 못하면 되돌리기가 원래 판으로 돌아온다"
  else
    say 틀림 "$name" "앞 판이 뜨지 못하면 되돌리기가 원래 판으로 돌아온다"
    $run 'cat /root/rollback3.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi
  $run 'rm -f /etc/callsignet/no-run'

  # 12. 판 이름으로 쓸 수 없는 값을 찍는 판. 어떤 디렉터리도 지우지 않고 거절한다.
  local before after okname=1
  before=$($run 'ls /opt/callsignet/versions | sort | tr "\n" " "')
  for bad in '' '..' 'x/y' '.'; do
    fake badname "#!/bin/sh
case \"\$1\" in
  version) echo '$bad' ;;
  *) exec $A \"\$@\" ;;
esac"
    if $run 'cd /root/badname && ./install.sh upgrade >/root/badname.log 2>&1'; then okname=0; fi
  done
  after=$($run 'ls /opt/callsignet/versions | sort | tr "\n" " "')
  if [ "$okname" = 1 ] && [ "$before" = "$after" ] && [ "$(cur)" = "$VER_B" ] && $run '[ -d /opt/callsignet/versions ] && [ -L /opt/callsignet/current ]' && answers; then
    say ok "$name" "빈 값이나 ..이나 슬래시가 든 판 이름은 어떤 디렉터리도 지우지 않고 거절한다"
  else
    say 틀림 "$name" "빈 값이나 ..이나 슬래시가 든 판 이름은 어떤 디렉터리도 지우지 않고 거절한다"
    echo "        앞: $before" ; echo "        뒤: $after"; $run 'cat /root/badname.log' | sed 's/^/        /'
  fi

  # 13. 링크를 옮긴 뒤에 서비스 파일을 쓰지 못하면 시도 전 그대로 돌아온다.
  #     서비스 파일을 잠가 두고, 서비스 파일이 다른 진짜 판으로 올린다.
  $run "rm -rf /root/unitdiff && cp -a /home/inst/a/csa-linux-amd64 /root/unitdiff && echo '# 시험용 한 줄' >> /root/unitdiff/csa.service && chattr +i /etc/systemd/system/csa.service"
  if ! $run 'cd /root/unitdiff && ./install.sh upgrade >/root/unitdiff.log 2>&1' \
     && $run 'grep -q "아무것도 바뀌지 않았습니다" /root/unitdiff.log' \
     && [ "$(cur)" = "$VER_B" ] && [ "$(prev)" = "$VER_A-flaky" ] \
     && $run 'cmp -s /opt/callsignet/current/csa.service /etc/systemd/system/csa.service' && answers; then
    say ok "$name" "링크를 옮긴 뒤 서비스 파일을 쓰지 못해도 링크와 서비스 파일이 시도 전 그대로 돌아온다"
  else
    say 틀림 "$name" "링크를 옮긴 뒤 서비스 파일을 쓰지 못해도 링크와 서비스 파일이 시도 전 그대로 돌아온다"
    $run 'cat /root/unitdiff.log; ./install.sh status 2>/dev/null' | sed 's/^/        /'
  fi
  $run 'chattr -i /etc/systemd/system/csa.service'

  # 14. 돌아오는 것마저 막히면 「반쯤」이라고 말한다. 뜨면서 /opt/callsignet 을
  #     잠그는 판으로 올린다. 그 뒤 서비스를 멈추고 잠금을 풀고 되돌리면 회복한다.
  if ! $run 'cd /root/lock && ./install.sh upgrade >/root/lock.log 2>&1' \
     && $run 'grep -q "반쯤" /root/lock.log && ! grep -q "돌아왔" /root/lock.log' \
     && [ "$(cur)" = "$VER_A-lock" ]; then
    say ok "$name" "돌아오지도 못하면 돌아왔다고 하지 않고 반쯤 옮겨진 상태라고 말한다"
  else
    say 틀림 "$name" "돌아오지도 못하면 돌아왔다고 하지 않고 반쯤 옮겨진 상태라고 말한다"
    $run 'cat /root/lock.log' | sed 's/^/        /'
  fi
  if $run 'systemctl stop csa; chattr -i /opt/callsignet && cd /root/lock && ./install.sh rollback >/root/rollback4.log 2>&1 && systemctl reset-failed csa && systemctl start csa' \
     && [ "$(cur)" = "$VER_B" ] && answers; then
    say ok "$name" "서비스를 멈추고 까닭을 치운 뒤 되돌리면 회복한다"
  else
    say 틀림 "$name" "서비스를 멈추고 까닭을 치운 뒤 되돌리면 회복한다"
    $run 'cat /root/rollback4.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi

  # 15. 지금 판의 이름이 <새 판>.tmp 여도 새 판을 두면서 지금 판을 지우지 않는다.
  #     이름이 x.tmp 인 판을 먼저 올리고, 이름이 x 인 판을 올린다.
  fake xtmp "#!/bin/sh
case \"\$1\" in
  version) echo $VER_A-x.tmp ;;
  *) exec $A \"\$@\" ;;
esac"
  fake x "#!/bin/sh
case \"\$1\" in
  version) echo $VER_A-x ;;
  *) exec $A \"\$@\" ;;
esac"
  if $run 'cd /root/xtmp && ./install.sh upgrade >/root/xtmp.log 2>&1' && [ "$(cur)" = "$VER_A-x.tmp" ] \
     && $run 'cd /root/x && ./install.sh upgrade >/root/x.log 2>&1' \
     && [ "$(cur)" = "$VER_A-x" ] && [ "$(prev)" = "$VER_A-x.tmp" ] \
     && $run "[ -x /opt/callsignet/versions/$VER_A-x.tmp/bin/csa ]" && answers; then
    say ok "$name" "지금 판의 이름이 새 판 이름에 .tmp를 붙인 것이어도 지금 판을 지우지 않는다"
  else
    say 틀림 "$name" "지금 판의 이름이 새 판 이름에 .tmp를 붙인 것이어도 지금 판을 지우지 않는다"
    $run 'cat /root/xtmp.log /root/x.log; ls /opt/callsignet/versions' | sed 's/^/        /'
  fi

  # 16. 지운다. 문서의 명령 그대로다.
  $run 'systemctl disable --now csa >/dev/null 2>&1; rm -f /etc/systemd/system/csa.service /usr/local/bin/csa; systemctl daemon-reload; rm -rf /opt/callsignet'
  if $run '! systemctl is-enabled csa >/dev/null 2>&1 && [ ! -e /usr/local/bin/csa ] && [ ! -e /opt/callsignet ] && [ -f /etc/callsignet/private.key ]'; then
    say ok "$name" "지우면 서비스와 링크와 판이 사라지고 설정은 남는다"
  else
    say 틀림 "$name" "지우면 서비스와 링크와 판이 사라지고 설정은 남는다"
  fi
  if $run '! ip link show cs0 >/dev/null 2>&1'; then
    say ok "$name" "멈춘 뒤 인터페이스가 남지 않는다"
  else
    say 틀림 "$name" "멈춘 뒤 인터페이스가 남지 않는다"
  fi
}

walk "Ubuntu" "$IP_A" inst-a 10.96.0.1
walk "Rocky" "$IP_B" inst-b 10.96.0.2

echo
mkdir -p "$RESULTS"
own "$RESULTS"
REPORT="$RESULTS/install-$(date -u +%Y%m%dT%H%M%SZ).md"
{
  echo "# 설치 시험 ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo
  echo "커밋 $(git -C "$REPO" rev-parse --short HEAD), csa의 판 $VER_A (올린 판 $VER_B)"
  echo "Ubuntu 24.04와 Rocky 9에서 각각 혼자 밟았다."
  echo
  echo "| 결과 | 머신 | 확인한 것 |"
  echo "|---|---|---|"
  printf '%s' "$SAID"
} > "$REPORT"
own "$REPORT"
echo "기록: ${REPORT#$REPO/}"
if [ "$ALL_OK" = 1 ]; then
  echo "확인됨. 깨끗한 머신 둘에서 설치하고 올리고 되돌렸다."
else
  echo "틀린 것이 있습니다. 위를 보십시오."
  exit 1
fi
