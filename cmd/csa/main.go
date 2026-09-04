// csa는 머신마다 하나 도는 Callsignet agent다.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/randyinthedev-hash/callsignet/internal/config"
	"github.com/randyinthedev-hash/callsignet/internal/control"
	"github.com/randyinthedev-hash/callsignet/internal/guard"
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
	case "status":
		err = runStatus(args)
	case "reload":
		err = runReload(args)
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

	gd := guard.New(logf)
	if err := gd.Apply(guardConfig(cfg)); err != nil {
		return err
	}
	defer gd.Close()

	// live는 csa가 지금 따르고 있는 설정이다. csa reload가 갈아 끼운다.
	var live atomic.Pointer[config.Config]
	live.Store(cfg)

	started := time.Now()
	ctl, err := control.Listen(cfg.Self.PeerID, func(req string) (string, error) {
		switch req {
		case "status":
			return statusJSON(live.Load(), dev, took, gd, started)
		case "reload":
			return reload(*dir, &live, dev, dnsSrv, gd, logf)
		}
		return "", fmt.Errorf("모르는 물음이다: %s", req)
	})
	if err != nil {
		return err
	}
	defer ctl.Close()
	logf("csa status를 받을 소켓을 열었습니다: %s", control.SocketPath(cfg.Self.PeerID))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	logf("csa가 돕니다. 멈추려면 Ctrl-C를 누르십시오.")
	<-stop
	logf("멈춥니다.")
	return nil
}

// statusJSON은 지금 상태를 모아 JSON으로 만든다. 설정에서 오는 값과 wg에게
// 물은 값을 합친다. peers.toml에 있지만 아직 세션을 맺지 않은 상대도 넣는다.
// guardConfig는 설정에서 직통 경로 규칙에 필요한 값을 뽑는다. 닫을 포트는
// peers.toml에 적힌 이 머신의 서비스 포트다.
func guardConfig(c *config.Config) guard.Config {
	mode, _ := guard.ParseMode(c.Self.Guard.Mode) // 검사에서 이미 걸렀다
	g := guard.Config{
		Mode:    mode,
		Iface:   c.Self.TunName(),
		WGPort:  c.Self.ListenPort,
		KeepTCP: c.Self.Guard.KeepTCP,
		KeepUDP: c.Self.Guard.KeepUDP,
	}
	if self := c.Find(c.Self.PeerID); self != nil {
		for _, svc := range self.Services {
			g.Ports = append(g.Ports, svc.Port)
		}
	}
	return g
}

func statusJSON(cfg *config.Config, dev *wgdev.Device, took *name.Takeover,
	gd *guard.Guard, started time.Time) (string, error) {
	self := cfg.Find(cfg.Self.PeerID)
	st := control.Status{
		PeerID:   cfg.Self.PeerID,
		Iface:    dev.Name,
		TunnelIP: self.TunnelIP,
		Domain:   cfg.Self.Domain,
		Resolver: took.Manager.String(),
		MTU:      cfg.Self.TunMTU(),
		MaxMSS:   dev.MaxMSS(),
		Clamped:  dev.MSSClamped(),
		Since:    started,

		Guard:        gd.Mode().String(),
		GuardBlocked: gd.Blocked(),
	}
	live := dev.Status()
	for _, p := range cfg.Peers {
		if p.PeerID == cfg.Self.PeerID {
			continue
		}
		row := control.PeerStatus{PeerID: p.PeerID, TunnelIP: p.TunnelIP}
		if w, ok := live[p.PeerID]; ok {
			row.Handshake = w.Handshake
			row.RxBytes, row.TxBytes = w.RxBytes, w.TxBytes
			// 접속 주소는 세션을 맺은 뒤에만 적는다. 아직 맺지 않았으면 wg가
			// 내놓는 값은 peers.toml에 적힌 주소이고, 그것은 csa가 관측한 것이
			// 아니다. 열 이름이 관측한 출발지이므로 그대로 적으면 틀린 말이 된다.
			if !w.Handshake.IsZero() {
				row.Endpoint = w.Endpoint
			}
		}
		st.Peers = append(st.Peers, row)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("상태를 JSON으로 만들지 못했다: %w", err)
	}
	return string(b), nil
}

// reload는 설정을 다시 읽어 걸 수 있는 것만 건다.
//
// peers.toml과 policy.toml은 도는 중에 갈아 끼울 수 있다. csa.toml은 그럴 수
// 없다. 거기 적힌 값은 TUN 인터페이스와 개인키와 리슨 주소를 정하므로 바꾸려면
// csa를 다시 띄워야 한다. csa.toml이 바뀌었으면 csa는 아무것도 걸지 않고 그
// 사실을 알린다. 반쯤 걸면 운영자가 무엇이 도는지 알 수 없다.
//
// 검사에 걸린 설정도 걸지 않는다. csa는 앞서 읽은 설정 그대로 계속 돈다.
func reload(dir string, live *atomic.Pointer[config.Config], dev *wgdev.Device,
	dnsSrv *name.Server, gd *guard.Guard, logf func(string, ...any)) (string, error) {

	cur, err := config.Load(dir)
	if err != nil {
		return "", fmt.Errorf("%w. 아무것도 바꾸지 않았다", err)
	}
	if problems := cur.Validate(); len(problems) > 0 {
		return "", fmt.Errorf("설정에 어긋난 곳이 %d군데 있다. 아무것도 바꾸지 않았다:\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	ch := config.Diff(live.Load(), cur)
	if ch.SelfChanged {
		return "", fmt.Errorf("csa.toml이 바뀌었다. 이 값은 도는 중에 바꿀 수 없다. " +
			"아무것도 바꾸지 않았다. csa를 다시 띄우라")
	}
	if ch.SelfPeerChanged {
		return "", fmt.Errorf("peers.toml에서 이 머신 자신의 공개키나 터널 IP가 바뀌었다. " +
			"이 값은 도는 중에 바꿀 수 없다. 아무것도 바꾸지 않았다. csa를 다시 띄우라")
	}
	if !ch.Any() {
		return "바뀐 것이 없습니다.\n", nil
	}

	table, err := name.NewTable(cur)
	if err != nil {
		return "", fmt.Errorf("%w. 아무것도 바꾸지 않았다", err)
	}
	if err := dev.Reload(cur); err != nil {
		return "", err
	}
	dnsSrv.SetTable(table)
	// 이 머신의 서비스 목록이 바뀌었으면 닫을 포트도 바뀐다.
	if err := gd.Apply(guardConfig(cur)); err != nil {
		return "", err
	}
	live.Store(cur)

	report := reloadReport(ch)
	logf("설정을 다시 읽었습니다. %s", strings.ReplaceAll(strings.TrimSpace(report), "\n", " "))
	return report, nil
}

func reloadReport(c config.Changes) string {
	var b strings.Builder
	b.WriteString("설정을 다시 읽었습니다.\n")
	if len(c.AddedPeers) > 0 {
		fmt.Fprintf(&b, "  더한 상대: %s\n", strings.Join(c.AddedPeers, ", "))
	}
	if len(c.RemovedPeers) > 0 {
		fmt.Fprintf(&b, "  뺀 상대: %s\n", strings.Join(c.RemovedPeers, ", "))
	}
	if len(c.ChangedPeers) > 0 {
		fmt.Fprintf(&b, "  고친 상대: %s\n", strings.Join(c.ChangedPeers, ", "))
	}
	if c.PolicyChanged {
		b.WriteString("  정책을 바꾸었습니다.\n")
	}
	return b.String()
}

// runReload는 도는 csa에게 설정을 다시 읽으라고 이른다. 다시 읽는 것은 도는
// csa가 자기가 기동할 때 받은 디렉터리에서 한다. 여기서 주는 -c는 어느 소켓에
// 붙을지 알아내는 데만 쓴다.
func runReload(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	dir := fs.String("c", "/etc/callsignet", "설정 디렉터리")
	fs.Parse(args)

	cfg, err := config.Load(*dir)
	if err != nil {
		return err
	}
	out, err := control.Ask(cfg.Self.PeerID, "reload")
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

// runStatus는 도는 csa에게 물어 상태를 찍는다. 설정 디렉터리를 읽는 것은
// 어느 소켓에 붙을지 알아내려는 것이다. 소켓 이름이 peer-id에서 온다.
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dir := fs.String("c", "/etc/callsignet", "설정 디렉터리")
	asJSON := fs.Bool("json", false, "표 대신 JSON으로 찍는다")
	fs.Parse(args)

	cfg, err := config.Load(*dir)
	if err != nil {
		return err
	}
	body, err := control.Ask(cfg.Self.PeerID, "status")
	if err != nil {
		return err
	}
	if *asJSON {
		fmt.Println(body)
		return nil
	}
	var st control.Status
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		return fmt.Errorf("답을 읽지 못했다: %w", err)
	}
	fmt.Print(control.Format(st, time.Now()))
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
