// csa는 머신마다 하나 도는 Callsignet agent다.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/randyinthedev-hash/callsignet/internal/config"
	"github.com/randyinthedev-hash/callsignet/internal/name"
	"github.com/randyinthedev-hash/callsignet/internal/wgdev"
)

const usage = `csa — Callsignet agent

사용법: csa <명령> [옵션]

  check    설정을 읽고 검사한다
  genkey   정적 키쌍을 만든다
  run      설정을 읽고 TUN 인터페이스를 만들고 돈다
  status   지금 붙어 있는 상대를 보여 준다
  reload   도는 중에 설정을 다시 읽는다
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "check":
		err = runCheck(args)
	case "genkey":
		err = runGenkey(args)
	case "run":
		err = runRun(args)
	case "status", "reload":
		err = fmt.Errorf("아직 만들지 않았습니다: %s", cmd)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dir := fs.String("c", "/etc/callsignet", "설정 디렉터리")
	fs.Parse(args)

	cfg, err := config.Load(*dir)
	if err != nil {
		return err
	}
	problems := cfg.Validate()
	if len(problems) == 0 {
		fmt.Printf("설정을 확인했습니다. peer %d개, 서비스 %d개입니다.\n",
			len(cfg.Peers), countServices(cfg))
		return nil
	}
	fmt.Fprintf(os.Stderr, "설정에 어긋난 곳이 %d군데 있습니다.\n\n", len(problems))
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "  "+p)
	}
	os.Exit(1)
	return nil
}

func runRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("c", "/etc/callsignet", "설정 디렉터리")
	fs.Parse(args)

	cfg, err := config.Load(*dir)
	if err != nil {
		return err
	}
	if problems := cfg.Validate(); len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "설정에 어긋난 곳이 %d군데 있습니다.\n\n", len(problems))
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  "+p)
		}
		return fmt.Errorf("설정을 고치고 다시 띄우십시오")
	}

	logf := func(f string, a ...any) { log.Printf(f, a...) }
	dev, err := wgdev.Open(cfg, logf)
	if err != nil {
		return err
	}
	defer dev.Close()

	table, err := name.NewTable(cfg)
	if err != nil {
		return err
	}
	self := cfg.Find(cfg.Self.PeerID)
	dnsSrv := name.NewServer(table, cfg.Self.DNS.TTL, logf)
	if err := dnsSrv.Start(cfg.Self.DNS.Listen, self.TunnelIP+":53"); err != nil {
		return err
	}
	defer dnsSrv.Close()

	revZone, err := name.ReverseZone(netip.MustParsePrefix(cfg.Self.TunnelCIDR))
	if err != nil {
		return err
	}
	took, err := name.Apply(dev.Name, cfg.Self.DNS.Listen, self.TunnelIP, cfg.Self.Domain, revZone, logf)
	if err != nil {
		return err
	}
	defer took.Close()

	machine := cfg.Self.PeerID + "." + cfg.Self.Domain
	if err := name.Verify(machine, netip.MustParseAddr(self.TunnelIP)); err != nil {
		logf("이름 해석 설정이 먹지 않았습니다: %v", err)
	} else {
		logf("이름 해석을 확인했습니다. %s가 %s로 풀립니다.", machine, self.TunnelIP)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	logf("csa가 돕니다. 멈추려면 Ctrl-C를 누르십시오.")
	<-stop
	logf("멈춥니다.")
	return nil
}

func countServices(c *config.Config) int {
	n := 0
	for _, p := range c.Peers {
		n += len(p.Services)
	}
	return n
}

func runGenkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("o", "", "개인키를 쓸 파일. 비우면 화면에 찍는다")
	fs.Parse(args)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// wg genkey와 같은 형태가 되도록 스칼라를 다듬는다.
	b := priv.Bytes()
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	clamped, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return err
	}
	privB64 := base64.StdEncoding.EncodeToString(clamped.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(clamped.PublicKey().Bytes())

	if *out == "" {
		fmt.Println(privB64)
		fmt.Fprintln(os.Stderr, "공개키:", pubB64)
		return nil
	}
	if err := os.WriteFile(*out, []byte(privB64+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("개인키를 %s에 썼습니다. 소유자만 읽을 수 있습니다.\n", *out)
	fmt.Println("공개키:", pubB64)
	return nil
}
