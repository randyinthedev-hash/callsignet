# VM 시험

네임스페이스로 하는 통합 시험이 밟지 못하는 것을 실제 머신에서 밟는다. 네임스페이스에는 진짜 NIC도 systemd도 NetworkManager도 firewalld도 없기 때문이다.

VM 둘을 띄운다. Ubuntu 24.04에는 systemd-resolved가 돌고 Rocky 9에는 NetworkManager와 firewalld가 돈다. csa가 그 셋을 건드리지 않고 자기 표 둘만 걸고 지우는지 본다. 진짜 NIC에서 커널이 목적지가 바뀐 패킷의 경로를 다시 찾는지, 엄격한 역경로 검사에서도 되돌아가는 패킷이 지나는지 본다. 터널도 여기서 처음으로 진짜 머신 둘 사이에서 확인한다.

## 준비물

```bash
sudo apt install -y qemu-system-x86 libvirt-daemon-system libvirt-clients virtinst cloud-image-utils
sudo systemctl enable --now libvirtd
```

## 돌리기

```bash
make build-static
sudo make vm
```

`csa`를 정적으로 만드는 까닭이 있다. Rocky 9의 glibc가 Ubuntu 24.04보다 낮아 동적으로 링크한 것은 Rocky에서 돌지 않는다.

바탕 이미지는 처음 한 번만 받아 `/var/lib/libvirt/images/`에 둔다. VM과 가상 망은 끝나면 지운다. `KEEP=1`을 주면 남긴다.

```bash
sudo KEEP=1 make vm     # 확인이 끝나도 VM을 남긴다
sudo make vm-teardown   # 남긴 것을 지운다
```

## 버스를 손으로 정하는 까닭

스크립트는 디스크를 `bus=virtio`에, 네트워크를 `model=virtio`에 붙인다. 이 머신에 `osinfo-db`가 없어 virt-install이 `generic`으로 떨어지고, 그러면 디스크를 virtio가 아닌 버스에 붙인다. Rocky 클라우드 이미지의 initramfs에는 그 버스의 드라이버가 없어 루트를 찾지 못하고 dracut 비상 셸로 떨어진다. Ubuntu는 드라이버를 넓게 담아 두어 그래도 뜬다.

## 무엇을 보나

건드리지 않는 것 셋을 본다. csa가 두 머신의 `/etc/resolv.conf`를 건드리지 않는가. systemd-resolved에 아무것도 등록하지 않는가. 이름 해석을 하지 않는가. 0.1.x의 csa는 이 셋을 모두 했다.

터널이 서는지 하나를 본다. 진짜 머신 둘 사이에서 터널 IP로 ping이 간다.

실제 IP로 부른 연결 넷을 본다. 시험 스크립트는 두 머신의 역경로 검사를 먼저 엄격으로 둔다. B의 실제 IP 하나에만 듣는 서버에 A의 앱이 B의 실제 IP로 붙어 자료가 오간다. B의 csa 기록에 peer-id가 남는다. 서버가 상대를 A의 실제 IP로 본다. `csa status`가 터널로 돌린 연결을 센다. 네임스페이스에서는 진짜 NIC가 없어 커널이 목적지가 바뀐 패킷의 경로를 NIC에서 TUN으로 다시 찾는 것을 보지 못한다.

직통 경로를 닫는 것 여섯을 본다. Rocky 클라우드 이미지에는 `nftables`도 firewalld도 없으므로 둘을 설치하고 firewalld를 켠다. 실제 RHEL 서버의 모양이다. firewalld에는 wg 포트와 앱 포트를 연다. firewalld가 앱 포트를 열어 두어도 csa가 직통 경로를 막는지, firewalld의 표 곁에 csa의 표 둘이 함께 도는지, 적지 않은 포트는 그대로 열려 있는지 본다. csa 없는 머신 노릇은 이 호스트가 한다.

멈춘 뒤에 되돌아오는지 셋을 본다. A에서 인터페이스가 사라지고, B에서 표 둘이 사라지고, B의 `/etc/resolv.conf`가 그대로다.

## 이 시험이 하지 않는 것

정책 집행과 MTU는 보지 않는다. 그것은 네임스페이스로 하는 통합 시험이 본다.
