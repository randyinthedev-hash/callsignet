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
walk() { # 이름 주소 peer-id 터널IP
  local name=$1 ip=$2 pid=$3 tip=$4
  local run="$SSH root@$ip"
  echo
  echo "== $name"

  $SSH "root@$ip" 'mkdir -p /root/a /root/b'
  $SCP "$WORK/a/csa-linux-amd64.tar.gz" "$WORK/a/sha256sum.txt" "root@$ip:/root/a/" >/dev/null
  $SCP "$WORK/b/csa-linux-amd64.tar.gz" "$WORK/b/sha256sum.txt" "root@$ip:/root/b/" >/dev/null

  # 1. 묶음을 확인하고 푼다.
  if $run 'cd /root/a && sha256sum -c --ignore-missing sha256sum.txt >/dev/null && tar -xzf csa-linux-amd64.tar.gz && cd /root/b && sha256sum -c --ignore-missing sha256sum.txt >/dev/null && tar -xzf csa-linux-amd64.tar.gz'; then
    say ok "$name" "묶음의 체크섬이 맞고 풀린다"
  else
    say 틀림 "$name" "묶음의 체크섬이 맞고 풀린다"; return
  fi

  # 2. 처음 설치. 설정이 없으므로 서비스는 켜져 있되 뜨지 않는다.
  if $run 'cd /root/a/csa-linux-amd64 && ./install.sh install >/root/install.log 2>&1'; then
    say ok "$name" "처음 설치가 끝난다"
  else
    say 틀림 "$name" "처음 설치가 끝난다"; $run 'cat /root/install.log' | sed 's/^/        /'; return
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
  if $run 'cd /root/b/csa-linux-amd64 && ./install.sh upgrade >/root/upgrade.log 2>&1' \
     && [ "$($run 'csa version')" = "$VER_B" ] && answers; then
    say ok "$name" "올리면 판이 $VER_B 이 되고 csa가 답한다"
  else
    say 틀림 "$name" "올리면 판이 $VER_B 이 되고 csa가 답한다"
    $run 'cat /root/upgrade.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi
  if [ "$($run 'basename $(readlink -f /opt/callsignet/previous)')" = "$VER_A" ]; then
    say ok "$name" "앞 판 링크가 $VER_A 을 가리킨다"
  else
    say 틀림 "$name" "앞 판 링크가 $VER_A 을 가리킨다"
  fi

  # 6. 되돌린다.
  if $run 'cd /root/b/csa-linux-amd64 && ./install.sh rollback >/root/rollback.log 2>&1' \
     && [ "$($run 'csa version')" = "$VER_A" ] && answers; then
    say ok "$name" "되돌리면 판이 $VER_A 이 되고 csa가 답한다"
  else
    say 틀림 "$name" "되돌리면 판이 $VER_A 이 되고 csa가 답한다"
    $run 'cat /root/rollback.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi

  # 7. 뜨지 못하는 판으로 올린다. 실행 파일 자리에 판만 말하고 뜨지는 않는
  #    스크립트를 둔다. 검사는 지금 판의 csa에 넘긴다. 올리기는 실패로 끝나야
  #    하고, 끝난 뒤에는 앞 판이 돌고 있어야 한다.
  $run "cp -a /root/b/csa-linux-amd64 /root/c && cat > /root/c/bin/csa <<'EOF'
#!/bin/sh
case \"\$1\" in
  version) echo $VER_A-bad ;;
  check) exec /opt/callsignet/versions/$VER_A/bin/csa \"\$@\" ;;
  *) echo '일부러 뜨지 않습니다' >&2; exit 1 ;;
esac
EOF
chmod 755 /root/c/bin/csa"
  if ! $run 'cd /root/c && ./install.sh upgrade >/root/bad.log 2>&1' \
     && [ "$($run 'csa version')" = "$VER_A" ] && answers; then
    say ok "$name" "뜨지 못하는 판으로 올리면 스스로 앞 판으로 되돌린다"
  else
    say 틀림 "$name" "뜨지 못하는 판으로 올리면 스스로 앞 판으로 되돌린다"
    $run 'cat /root/bad.log; journalctl -u csa --no-pager | tail -20' | sed 's/^/        /'
  fi

  # 8. 지운다. 문서의 명령 그대로다.
  $run 'systemctl disable --now csa >/dev/null 2>&1; rm -f /etc/systemd/system/csa.service /usr/local/bin/csa; systemctl daemon-reload; rm -rf /opt/callsignet'
  if $run '! systemctl is-enabled csa >/dev/null 2>&1 && [ ! -e /usr/local/bin/csa ] && [ ! -e /opt/callsignet ] && [ -f /etc/callsignet/private.key ]'; then
    say ok "$name" "지우면 서비스와 링크와 판이 사라지고 설정은 남는다"
  else
    say 틀림 "$name" "지우면 서비스와 링크와 판이 사라지고 설정은 남는다"
  fi
  # 멈추면서 되돌렸는지도 본다. 인터페이스가 남아 있으면 되돌리지 못한 것이다.
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
