package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const notices = `# 고지

| 라이브러리 | 판 | 라이선스 |
|---|---|---|
| ` + "`github.com/BurntSushi/toml`" + ` | v1.4.0 | MIT |
`

// repoRoot는 이 모듈의 뿌리다. 시험 실행 파일을 거기서 만들어야 buildinfo에
// vcs.revision이 찍힌다.
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Skip("go env GOMOD를 읽지 못했다")
	}
	return filepath.Dir(strings.TrimSpace(string(out)))
}

// buildHello는 testdata/hello를 리눅스 amd64 실행 파일로 만든다. 커밋 해시와
// 작업 나무가 깨끗한지도 함께 돌려준다.
func buildHello(t *testing.T) (bin []byte, commit string, modified bool) {
	t.Helper()
	root := repoRoot(t)
	rev, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Skip("git 리포가 아니다")
	}
	commit = strings.TrimSpace(string(rev))
	status, _ := exec.Command("git", "-C", root, "status", "--porcelain").Output()
	modified = len(bytes.TrimSpace(status)) > 0
	out := filepath.Join(t.TempDir(), "hello")
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./tools/sbom/testdata/hello")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("시험 실행 파일을 만들지 못했다: %v\n%s", err, msg)
	}
	bin, err = os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return bin, commit, modified
}

// stage는 묶음 디렉터리를 만든다.
func stage(t *testing.T, bin []byte) (string, spec) {
	t.Helper()
	root := repoRoot(t)
	rev, _ := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	dir := filepath.Join(t.TempDir(), "hello-linux-amd64")
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"install.sh":             "#!/bin/sh\necho 설치\n",
		"LICENSE":                "라이선스 본문\n",
		"INSTALL.md":             "# 설치\n",
		"THIRD-PARTY-NOTICES.md": notices,
		"hello.service":          "[Unit]\nDescription=hello\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "hello"), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	status, _ := exec.Command("git", "-C", root, "status", "--porcelain").Output()
	s := spec{
		program: "hello", arch: "amd64", version: "0.1.6",
		commit: strings.TrimSpace(string(rev)), repo: "example/hello", license: "Apache-2.0",
		allowModified: len(bytes.TrimSpace(status)) > 0,
	}
	m, err := ownModule()
	if err != nil {
		t.Fatal(err)
	}
	s.module = m
	return dir, s
}

// pack은 묶음 디렉터리를 tar.gz로 만든다. extra로 이상한 항목을 더할 수 있다.
func pack(t *testing.T, dir string, extra func(*tar.Writer)) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), filepath.Base(dir)+".tar.gz")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	base := filepath.Base(dir)
	if err := tw.WriteHeader(&tar.Header{Name: base + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		name := base + "/" + filepath.ToSlash(rel)
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))}); err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		extra(tw)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

func args(s spec, more ...string) []string {
	a := []string{"-program", s.program, "-arch", s.arch, "-version", s.version, "-commit", s.commit,
		"-repo", s.repo, "-license", s.license, "-module", s.module}
	if s.allowModified {
		a = append(a, "-allow-modified")
	}
	return append(a, more...)
}

func TestMake와Verify가서로맞는다(t *testing.T) {
	bin, _, _ := buildHello(t)
	dir, s := stage(t, bin)
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatalf("SBOM을 만들지 못했다: %v", err)
	}
	var doc document
	b, err := os.ReadFile(filepath.Join(dir, sbomName))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || len(doc.Files) != 6 {
		t.Fatalf("문서가 다르다. 판 %s, 파일 %d", doc.SPDXVersion, len(doc.Files))
	}
	var deps []string
	for _, p := range doc.Packages {
		if strings.HasPrefix(p.ID, "SPDXRef-Package-github.com") {
			deps = append(deps, p.Name+"@"+p.Version+" "+p.LicenseConcluded)
		}
	}
	if len(deps) != 1 || deps[0] != "github.com/BurntSushi/toml@v1.4.0 MIT" {
		t.Fatalf("의존 모듈이 다르다: %v", deps)
	}
	tarPath := pack(t, dir, nil)
	copyPath := filepath.Join(t.TempDir(), "hello-linux-amd64.spdx.json")
	if err := os.WriteFile(copyPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runVerify(args(s, "-tar", tarPath, "-copy", copyPath)); err != nil {
		t.Fatalf("맞는 묶음을 거절했다: %v", err)
	}
	// 두 번 만들어도 시각 말고는 같다.
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatal(err)
	}
}

func TestVerify는고친파일과이상한항목을잡는다(t *testing.T) {
	bin, _, _ := buildHello(t)
	dir, s := stage(t, bin)
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatal(err)
	}
	// 설치 스크립트를 SBOM 뒤에 고친다.
	if err := os.WriteFile(filepath.Join(dir, "install.sh"), []byte("#!/bin/sh\nrm -rf /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runVerify(args(s, "-tar", pack(t, dir, nil)))
	if err == nil || !strings.Contains(err.Error(), "해시가 다르다: install.sh") {
		t.Fatalf("고친 설치 스크립트를 잡지 못했다: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "install.sh"), []byte("#!/bin/sh\necho 설치\n"), 0o644)
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatal(err)
	}
	// 심볼릭 링크
	err = runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: "hello-linux-amd64/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	})))
	if err == nil || !strings.Contains(err.Error(), "다른 것이 있다") {
		t.Fatalf("심볼릭 링크를 잡지 못했다: %v", err)
	}
	// 위로 나가는 경로
	err = runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: "hello-linux-amd64/../x", Typeflag: tar.TypeReg, Size: 0})
	})))
	if err == nil || !strings.Contains(err.Error(), "위험한 경로") && !strings.Contains(err.Error(), "맨 위 디렉터리") {
		t.Fatalf("위로 나가는 경로를 잡지 못했다: %v", err)
	}
	// SBOM에 없는 파일이 더 들어 있다.
	err = runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: "hello-linux-amd64/extra", Typeflag: tar.TypeReg, Size: 0})
	})))
	if err == nil || !strings.Contains(err.Error(), "SBOM에 없다: extra") {
		t.Fatalf("더 들어간 파일을 잡지 못했다: %v", err)
	}
	// 다른 커밋, 다른 아키텍처
	wrong := s
	wrong.commit = strings.Repeat("0", 40)
	err = runVerify(args(wrong, "-tar", pack(t, dir, nil)))
	if err == nil || !strings.Contains(err.Error(), "vcs.revision") {
		t.Fatalf("다른 커밋을 잡지 못했다: %v", err)
	}
	wrong = s
	wrong.arch = "arm64"
	err = runVerify(args(wrong, "-tar", pack(t, dir, nil)))
	if err == nil || !strings.Contains(err.Error(), "맨 위 디렉터리") {
		t.Fatalf("다른 아키텍처를 잡지 못했다: %v", err)
	}
	// 고지 문서에 없는 모듈
	if err := os.WriteFile(filepath.Join(dir, "THIRD-PARTY-NOTICES.md"), []byte("| `github.com/other/lib` | v1.0.0 | MIT |\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = runMake(args(s, "-dir", dir))
	if err == nil || !strings.Contains(err.Error(), "고지 문서의 표에 없다") {
		t.Fatalf("고지 문서와 다른 것을 잡지 못했다: %v", err)
	}
}

func TestVerificationCode는SPDX의셈법이다(t *testing.T) {
	// 파일 a와 b. SHA-1을 정렬해 이어 붙인 것의 SHA-1이다.
	entries := []entry{{name: "b", sha1: sum1("b")}, {name: "a", sha1: sum1("a")}, {name: sbomName, sha1: sum1("x")}}
	want := sum1(sum1("a") + sum1("b"))
	if got := verificationCodeOf(entries); got != want {
		t.Fatalf("검증 코드가 다르다: %s", got)
	}
}

func sum1(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestReadNotices는리포의고지문서를읽는다(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "THIRD-PARTY-NOTICES.md"))
	if err != nil {
		t.Fatal(err)
	}
	table, err := readNotices(b)
	if err != nil {
		t.Fatal(err)
	}
	if table["github.com/BurntSushi/toml@v1.4.0"] != "MIT" || len(table) < 5 {
		t.Fatalf("표를 잘못 읽었다: %v", table)
	}
	if _, err := readNotices([]byte("| `a` | v1 | 모르는 라이선스 |\n")); err == nil {
		t.Fatal("모르는 라이선스 이름을 받아들였다")
	}
}

func bundleFile(t *testing.T, dir, name, predicate, subject, digest string) string {
	t.Helper()
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predicate,
		"subject":       []map[string]any{{"name": subject, "digest": map[string]string{"sha256": digest}}},
		"predicate":     map[string]any{},
	}
	raw, _ := json.Marshal(st)
	bundle := map[string]any{
		"mediaType":    "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(raw), "payloadType": "application/vnd.in-toto+json"},
	}
	pretty, _ := json.MarshalIndent(bundle, "", "  ")
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pretty, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestJSONL은두증명을한줄씩담고어긋남을잡는다(t *testing.T) {
	dir := t.TempDir()
	d := strings.Repeat("ab", 32)
	prov := bundleFile(t, dir, "prov.json", provenanceType, "x.tar.gz", d)
	sbom := bundleFile(t, dir, "sbom.json", spdxType, "x.tar.gz", d)
	out := filepath.Join(dir, "x.jsonl")
	if err := runJSONL([]string{"-out", out, prov, sbom}); err != nil {
		t.Fatalf("합치지 못했다: %v", err)
	}
	b, _ := os.ReadFile(out)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 || strings.Contains(lines[0], "\n ") {
		t.Fatalf("두 줄이 아니거나 정규화되지 않았다: %q", b)
	}
	other := bundleFile(t, dir, "other.json", spdxType, "y.tar.gz", d)
	if err := runJSONL([]string{"-out", out, prov, other}); err == nil || !strings.Contains(err.Error(), "대상이 다르다") {
		t.Fatalf("다른 대상을 잡지 못했다: %v", err)
	}
	if err := runJSONL([]string{"-out", out, prov, prov}); err == nil || !strings.Contains(err.Error(), "같은 predicate") {
		t.Fatalf("같은 predicate 둘을 잡지 못했다: %v", err)
	}
	unknown := bundleFile(t, dir, "unknown.json", "https://example.com/other", "x.tar.gz", d)
	if err := runJSONL([]string{"-out", out, prov, unknown}); err == nil || !strings.Contains(err.Error(), "모르는 predicate") {
		t.Fatalf("모르는 predicate를 잡지 못했다: %v", err)
	}
}

func TestSpec은모양을본다(t *testing.T) {
	s := spec{program: "csa", arch: "amd64", version: "v0.1.6", commit: "abc", repo: "x", license: ""}
	err := s.check()
	if err == nil {
		t.Fatal("틀린 옵션을 받아들였다")
	}
	for _, want := range []string{"-version", "-commit", "-repo", "-license"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%s 를 짚지 않았다: %v", want, err)
		}
	}
}
