# VM 시험

네임스페이스 하네스가 밟지 못하는 것을 실제 머신에서 밟는다. 네임스페이스에는 systemd도 NetworkManager도 없어 리졸버 갈래 가운데 하나만 확인할 수 있기 때문이다.

VM 둘을 띄운다. Ubuntu 24.04에는 systemd-resolved가 돌고 Rocky 9에는 NetworkManager가 돈다. 두 머신에서 csa가 어느 갈래를 타고 이름이 실제로 풀리는지 본다. 터널도 여기서 처음으로 진짜 머신 둘 사이에서 확인한다.

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

Ubuntu에서 넷을 본다. csa가 systemd-resolved 갈래를 타는가. `/etc/resolv.conf`를 건드리지 않는가. `cs0`에 내부 도메인을 등록하는가. 역방향 구역도 등록하는가.

Rocky에서는 csa가 판별한 관리 주체를 찍고, 파일 첫 줄을 가져갔는지 본다. 30초 뒤에도 그 줄이 남아 있는지 함께 본다. NetworkManager가 되돌리는지 보려는 것이다.

두 머신에서 이름이 시스템 경로로 풀리는지 셋을 본다. 서로의 서비스 이름과 역방향이다. `getent`로 묻는 까닭은 csa에게 바로 묻지 않고 운영체제가 가는 길을 그대로 밟으려는 것이다.

터널로 통신되는지 둘을 본다. 터널 IP로 한 번, 이름으로 한 번이다.

멈춘 뒤에 되돌아오는지 둘을 본다.

## 이 시험이 하지 않는 것

정책 집행과 직통 경로와 MTU는 보지 않는다. 그것은 네임스페이스 하네스가 본다. 여기서는 `guard.mode`를 `off`로 두어 방화벽을 건드리지 않는다. Rocky의 firewalld는 wg 포트를 막으므로 기동할 때 끈다.
