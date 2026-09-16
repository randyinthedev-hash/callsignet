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

// goLicense는 이 도구 사슬의 LICENSE 원문이다. 고지 문서의 Go 절이 이것과 같아야 한다.
func goLicenseOfToolchain(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Skip("go env GOROOT를 읽지 못했다")
	}
	b, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(b), "\n")
}

// noticesWith는 시험용 고지 문서다. 표의 행과 Go의 원문을 넣는다.
func noticesWith(t *testing.T, rows string, goText string) string {
	t.Helper()
	return "# 고지\n\n| 라이브러리 | 판 | 라이선스 |\n|---|---|---|\n" + rows +
		"\n" + goHeading + "\n\n```\n" + goText + "\n```\n\n## github.com/BurntSushi/toml v1.4.0\n\n```\nMIT\n```\n"
}

const tomlRow = "| `github.com/BurntSushi/toml` | v1.4.0 | MIT |\n"

// buildFixture는 testdata의 프로그램을 리눅스 amd64 실행 파일로 만든다.
func buildFixture(t *testing.T, prog string) []byte {
	t.Helper()
	root := repoRoot(t)
	if _, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output(); err != nil {
		t.Skip("git 리포가 아니다")
	}
	out := filepath.Join(t.TempDir(), prog)
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./tools/sbom/testdata/"+prog)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("시험 실행 파일을 만들지 못했다: %v\n%s", err, msg)
	}
	bin, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

// stage는 csa의 묶음 디렉터리를 계약의 파일 집합대로 만든다. 실행 파일은
// testdata의 fixture이고 주 패키지 경로를 그것으로 준다.
func stage(t *testing.T, program, fixture string, bin []byte) (string, spec) {
	t.Helper()
	root := repoRoot(t)
	rev, _ := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	status, _ := exec.Command("git", "-C", root, "status", "--porcelain").Output()
	m, err := ownModule()
	if err != nil {
		t.Fatal(err)
	}
	s := spec{
		program: program, arch: "amd64", version: "0.1.7",
		commit: strings.TrimSpace(string(rev)), repo: "example/thing", license: "Apache-2.0",
		module: m, pkgPath: m + "/tools/sbom/testdata/" + fixture,
		allowModified: len(bytes.TrimSpace(status)) > 0,
	}
	dir := filepath.Join(t.TempDir(), s.bundle())
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"install.sh": "#!/bin/sh\necho 설치\n",
		"LICENSE":    "Apache License\nVersion 2.0, January 2004\n",
		"INSTALL.md": "# 설치\n",
		noticesName:  noticesWith(t, tomlRow, goLicenseOfToolchain(t)),
	}
	if programs[program] {
		files[program+".service"] = "[Unit]\nDescription=" + program + "\n"
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", program), bin, 0o755); err != nil {
		t.Fatal(err)
	}
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
		"-repo", s.repo, "-license", s.license, "-module", s.module, "-package", s.pkgPath}
	if s.allowModified {
		a = append(a, "-allow-modified")
	}
	return append(a, more...)
}

func readDoc(t *testing.T, dir string) (document, []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, sbomName))
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, b
}

func writeDoc(t *testing.T, dir string, doc document) {
	t.Helper()
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sbomName), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func packages(doc document) map[string]pkg {
	out := map[string]pkg{}
	for _, p := range doc.Packages {
		out[p.ID] = p
	}
	return out
}

func wantErr(t *testing.T, err error, what string, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s를 잡지 못했다: 오류 없음", what)
	}
	for _, p := range parts {
		if strings.Contains(err.Error(), p) {
			return
		}
	}
	t.Fatalf("%s를 잡지 못했다: %v", what, err)
}

func TestMake와Verify가서로맞는다(t *testing.T) {
	bin := buildFixture(t, "hello")
	dir, s := stage(t, "csa", "hello", bin)
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatalf("SBOM을 만들지 못했다: %v", err)
	}
	doc, b := readDoc(t, dir)
	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || len(doc.Files) != 6 {
		t.Fatalf("문서가 다르다. 판 %s, dataLicense %s, 파일 %d", doc.SPDXVersion, doc.DataLicense, len(doc.Files))
	}
	pk := packages(doc)
	if p := pk["SPDXRef-Package-github.com-BurntSushi-toml"]; p.Version != "v1.4.0" || p.LicenseConcluded != "MIT" {
		t.Fatalf("의존 모듈이 다르다: %+v", p)
	}
	if len(doc.Packages) != 5 {
		t.Fatalf("Package가 다섯이 아니다: %d", len(doc.Packages))
	}
	want := "Apache-2.0 AND BSD-3-Clause AND MIT"
	if pk[idBundle].LicenseConcluded != want || pk[idBundle].LicenseDeclared != "Apache-2.0" {
		t.Fatalf("묶음의 라이선스가 다르다: %s / %s", pk[idBundle].LicenseDeclared, pk[idBundle].LicenseConcluded)
	}
	if pk[idGo].Version == "" || pk[idStdlib].Version != pk[idGo].Version || !strings.Contains(pk[idStdlib].Comment, "LICENSE sha256 "+sha256Hex(goLicenseOfToolchain(t))) {
		t.Fatalf("Go의 두 Package가 다르다: %+v / %+v", pk[idGo], pk[idStdlib])
	}
	lic := map[string]string{}
	for _, f := range doc.Files {
		lic[f.Name] = f.LicenseConcluded
	}
	if lic["./bin/csa"] != want || lic["./LICENSE"] != "NOASSERTION" || lic["./"+noticesName] != "NOASSERTION" || lic["./install.sh"] != "Apache-2.0" || lic["./csa.service"] != "Apache-2.0" {
		t.Fatalf("파일의 라이선스가 다르다: %v", lic)
	}
	rels := map[string]bool{}
	for _, r := range doc.Relationships {
		rels[r.From+" "+r.Type+" "+r.To] = true
	}
	for _, r := range []string{
		idGo + " BUILD_TOOL_OF " + spdxID("File", "bin/csa"),
		idMain + " STATIC_LINK " + idStdlib,
		idMain + " STATIC_LINK SPDXRef-Package-github.com-BurntSushi-toml",
		spdxID("File", "bin/csa") + " GENERATED_FROM " + idMain,
	} {
		if !rels[r] {
			t.Fatalf("관계가 없다: %s", r)
		}
	}
	tarPath := pack(t, dir, nil)
	copyPath := filepath.Join(t.TempDir(), s.bundle()+".spdx.json")
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
	// 바이트가 다른 사본
	if err := os.WriteFile(copyPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, nil), "-copy", copyPath)), "다른 사본", "사본이 묶음 안의 것과 다르다")
}

func TestVerify는고친파일과이상한항목을잡는다(t *testing.T) {
	bin := buildFixture(t, "hello")
	dir, s := stage(t, "csa", "hello", bin)
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatal(err)
	}
	base := s.bundle()
	// 설치 스크립트를 SBOM 뒤에 고친다.
	if err := os.WriteFile(filepath.Join(dir, "install.sh"), []byte("#!/bin/sh\nrm -rf /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, nil))), "고친 설치 스크립트", "해시가 다르다: install.sh")
	os.WriteFile(filepath.Join(dir, "install.sh"), []byte("#!/bin/sh\necho 설치\n"), 0o644)
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatal(err)
	}
	// 서비스 파일이 빠졌다.
	svc, _ := os.ReadFile(filepath.Join(dir, "csa.service"))
	os.Remove(filepath.Join(dir, "csa.service"))
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, nil))), "빠진 서비스 파일", "있어야 하는 파일이 없다: csa.service")
	os.WriteFile(filepath.Join(dir, "csa.service"), svc, 0o644)
	// 심볼릭 링크
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: base + "/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	}))), "심볼릭 링크", "다른 것이 있다")
	// 위로 나가는 경로
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: base + "/../x", Typeflag: tar.TypeReg, Size: 0})
	}))), "위로 나가는 경로", "위험한 경로", "맨 위 디렉터리")
	// 정리하면 지나가는 경로. a/../sbom.spdx.json 은 정리하면 sbom.spdx.json 이다.
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: base + "/a/../sbom.spdx.json", Typeflag: tar.TypeReg, Size: 0})
	}))), "정리하면 지나가는 경로", "위험한 경로")
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: base + "/./LICENSE", Typeflag: tar.TypeReg, Size: 0})
	}))), ". 조각", "위험한 경로")
	// 같은 이름이 둘
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: base + "/sbom.spdx.json", Typeflag: tar.TypeReg, Size: 2})
		tw.Write([]byte("{}"))
	}))), "같은 이름 둘", "같은 이름이 둘")
	// 계약에 없는 파일이 더 들어 있다.
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: base + "/extra", Typeflag: tar.TypeReg, Size: 0})
	}))), "더 들어간 파일", "계약에 없는 파일이 있다: extra")
	// 다른 커밋, 다른 아키텍처
	wrong := s
	wrong.commit = strings.Repeat("0", 40)
	wantErr(t, runVerify(args(wrong, "-tar", pack(t, dir, nil))), "다른 커밋", "vcs.revision")
	wrong = s
	wrong.arch = "arm64"
	wantErr(t, runVerify(args(wrong, "-tar", pack(t, dir, nil))), "다른 아키텍처", "맨 위 디렉터리")
	// 같은 모듈의 다른 프로그램의 실행 파일을 csa의 자리에 넣는다.
	other := buildFixture(t, "other")
	os.WriteFile(filepath.Join(dir, "bin", "csa"), other, 0o755)
	wantErr(t, runMake(args(s, "-dir", dir)), "다른 프로그램의 실행 파일", "주 패키지 경로가 다르다")
	os.WriteFile(filepath.Join(dir, "bin", "csa"), bin, 0o755)
}

func TestVerify는부품목록의값을하나하나견준다(t *testing.T) {
	bin := buildFixture(t, "hello")
	dir, s := stage(t, "csa", "hello", bin)
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatal(err)
	}
	const toml = "SPDXRef-Package-github.com-BurntSushi-toml"
	tamper := func(what string, f func(*document), parts ...string) {
		t.Helper()
		if err := runMake(args(s, "-dir", dir)); err != nil {
			t.Fatal(err)
		}
		doc, _ := readDoc(t, dir)
		f(&doc)
		writeDoc(t, dir, doc)
		wantErr(t, runVerify(args(s, "-tar", pack(t, dir, nil))), what, parts...)
	}
	edit := func(doc *document, id string, f func(*pkg)) {
		for i := range doc.Packages {
			if doc.Packages[i].ID == id {
				f(&doc.Packages[i])
			}
		}
	}
	tamper("같은 경로에 다른 판", func(d *document) { edit(d, toml, func(p *pkg) { p.Version = "v1.3.0" }) }, "경로나 판이 다르다")
	tamper("같은 경로에 다른 해시", func(d *document) { edit(d, toml, func(p *pkg) { p.Comment = "go.sum h1:AAAA" }) }, "go.sum 해시가 주석에 없거나 다르다")
	tamper("없는 교체 정보", func(d *document) {
		edit(d, toml, func(p *pkg) { p.Comment += ". example.com/x@v1 을 이것으로 바꿔 넣었다" })
	}, "바꾸지 않은 의존 모듈에 교체 정보가 있다")
	tamper("다른 라이선스", func(d *document) { edit(d, toml, func(p *pkg) { p.LicenseConcluded = "BSD-3-Clause" }) }, "라이선스가 고지 문서와 다르다")
	tamper("buildinfo에 없는 모듈", func(d *document) {
		d.Packages = append(d.Packages, pkg{Name: "example.com/ghost", ID: "SPDXRef-Package-example.com-ghost", Version: "v1.0.0", DownloadLocation: "NOASSERTION", LicenseConcluded: "MIT", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"})
	}, "계약에도 buildinfo에도 없는 Package가 SBOM에 있다: SPDXRef-Package-example.com-ghost")
	// 생성기가 쓰는 접두사가 아닌 식별자로 더한 Package도 잡아야 한다.
	tamper("다른 접두사의 추가 Package", func(d *document) {
		d.Packages = append(d.Packages, pkg{Name: "example.com/ghost", ID: "SPDXRef-Ghost", Version: "v1.0.0", DownloadLocation: "NOASSERTION", LicenseConcluded: "MIT", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"})
	}, "계약에도 buildinfo에도 없는 Package가 SBOM에 있다: SPDXRef-Ghost")
	tamper("같은 Package 식별자 둘", func(d *document) {
		for _, p := range d.Packages {
			if p.ID == toml {
				d.Packages = append(d.Packages, p)
			}
		}
	}, "같은 식별자가 둘 있다: "+toml)
	tamper("같은 File 항목 둘", func(d *document) { d.Files = append(d.Files, d.Files[0]) }, "같은 파일이 둘 있다")
	tamper("File과 겹치는 Package 식별자", func(d *document) {
		for i := range d.Files {
			if d.Files[i].Name == "./install.sh" {
				d.Files[i].ID = idStdlib
			}
		}
	}, "같은 식별자가 둘 있다: "+idStdlib)
	// 실행 파일은 그대로 두고 SBOM에 적힌 커밋만 바꾸거나 지운다. 실행 파일의 커밋을
	// 바꾸는 시험과는 다른 자리다.
	tamper("주석의 다른 커밋", func(d *document) {
		edit(d, idMain, func(p *pkg) { p.Comment = strings.Replace(p.Comment, s.commit, strings.Repeat("0", 40), 1) })
	}, "주석에 적힌 커밋이 다르다")
	tamper("주석에서 지운 커밋", func(d *document) {
		edit(d, idMain, func(p *pkg) { p.Comment = "주 패키지 " + s.pkgPath })
	}, "주석에 적힌 커밋이 다르다")
	tamper("빠진 Go 도구 사슬", func(d *document) {
		var keep []pkg
		for _, p := range d.Packages {
			if p.ID != idGo {
				keep = append(keep, p)
			}
		}
		d.Packages = keep
	}, "Go 도구 사슬 Package가 없거나")
	tamper("다른 Go 원문 해시", func(d *document) { edit(d, idStdlib, func(p *pkg) { p.Comment = goComment("go0", "00") }) }, "LICENSE 해시가 고지 문서의 Go 원문과 다르다")
	tamper("다른 묶음 라이선스", func(d *document) { edit(d, idBundle, func(p *pkg) { p.LicenseConcluded = "Apache-2.0" }) }, "묶음 Package의 라이선스가 다르다")
	tamper("LICENSE 파일에 내린 결론", func(d *document) {
		for i := range d.Files {
			if d.Files[i].Name == "./LICENSE" {
				d.Files[i].LicenseConcluded = "Apache-2.0"
			}
		}
	}, "파일의 라이선스가 계약과 다르다: LICENSE")
	tamper("빠진 BUILD_TOOL_OF", func(d *document) {
		var keep []relationship
		for _, r := range d.Relationships {
			if r.Type != "BUILD_TOOL_OF" {
				keep = append(keep, r)
			}
		}
		d.Relationships = keep
	}, "BUILD_TOOL_OF가 아니다")
}

func TestMake는고지문서와모듈집합을두방향으로견준다(t *testing.T) {
	bin := buildFixture(t, "hello")
	dir, s := stage(t, "csa", "hello", bin)
	goText := goLicenseOfToolchain(t)
	set := func(rows string, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, noticesName), []byte(noticesWith(t, rows, text)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 표에 실행 파일의 모듈이 없다.
	set("| `github.com/other/lib` | v1.0.0 | MIT |\n", goText)
	wantErr(t, runMake(args(s, "-dir", dir)), "표에서 빠진 모듈", "고지 문서의 표에 없다: github.com/BurntSushi/toml@v1.4.0")
	// 표가 실행 파일에 없는 모듈을 적었다.
	set(tomlRow+"| `github.com/other/lib` | v1.0.0 | MIT |\n", goText)
	wantErr(t, runMake(args(s, "-dir", dir)), "표에 더 적은 것", "실행 파일에 없다: github.com/other/lib@v1.0.0")
	// 표의 판이 다르다.
	set("| `github.com/BurntSushi/toml` | v1.3.0 | MIT |\n", goText)
	wantErr(t, runMake(args(s, "-dir", dir)), "표의 다른 판", "고지 문서의 표에 없다: github.com/BurntSushi/toml@v1.4.0")
	// 모르는 라이선스 이름
	set("| `github.com/BurntSushi/toml` | v1.4.0 | 모르는 라이선스 |\n", goText)
	wantErr(t, runMake(args(s, "-dir", dir)), "모르는 라이선스 이름", "라이선스 이름을 모른다")
	// Go의 원문이 다르다.
	set(tomlRow, "Copyright 2009 The Go Authors.\n")
	wantErr(t, runMake(args(s, "-dir", dir)), "다른 Go 원문", "Go 원문이 이 도구 사슬의 GOROOT/LICENSE와 다르다")
	// 원문 절이 없다.
	if err := os.WriteFile(filepath.Join(dir, noticesName), []byte("# 고지\n\n| 라이브러리 | 판 | 라이선스 |\n|---|---|---|\n"+tomlRow+"\n"+goHeading+"\n\n```\n"+goText+"\n```\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantErr(t, runMake(args(s, "-dir", dir)), "원문 절이 없는 모듈", "원문 절이 없다: github.com/BurntSushi/toml@v1.4.0")
	// Go 절이 없다.
	if err := os.WriteFile(filepath.Join(dir, noticesName), []byte("# 고지\n\n| 라이브러리 | 판 | 라이선스 |\n|---|---|---|\n"+tomlRow), 0o644); err != nil {
		t.Fatal(err)
	}
	wantErr(t, runMake(args(s, "-dir", dir)), "Go 절이 없는 고지 문서", "절이 없다")
	// 다시 맞는 문서를 두면 만들어지고, 만든 뒤 고지 문서의 Go 원문을 고치면 검사가 잡는다.
	set(tomlRow, goText)
	if err := runMake(args(s, "-dir", dir)); err != nil {
		t.Fatal(err)
	}
	set(tomlRow, goText+"\n덧붙인 줄")
	wantErr(t, runVerify(args(s, "-tar", pack(t, dir, nil))), "만든 뒤 고친 Go 원문", "해시가 다르다: "+noticesName, "GOROOT/LICENSE와 다르다")
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

func TestLicenseExpr는이은식이다(t *testing.T) {
	if got := licenseExpr("Apache-2.0", nil); got != "Apache-2.0 AND BSD-3-Clause" {
		t.Fatalf("의존 모듈이 없을 때의 식이 다르다: %s", got)
	}
	// 이 리포의 라이선스와 같은 의존 모듈의 라이선스는 한 번만 적는다.
	got := licenseExpr("Apache-2.0", map[string]string{"a@v1": "MIT", "b@v1": "Apache-2.0", "c@v1": "MIT", "d@v1": "BSD-3-Clause"})
	if got != "Apache-2.0 AND BSD-3-Clause AND MIT" {
		t.Fatalf("식이 다르다: %s", got)
	}
}

func TestReadNotices는리포의고지문서를읽는다(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), noticesName))
	if err != nil {
		t.Fatal(err)
	}
	n, err := readNotices(b)
	if err != nil {
		t.Fatal(err)
	}
	if n.table["github.com/BurntSushi/toml@v1.4.0"] != "MIT" || len(n.table) < 5 {
		t.Fatalf("표를 잘못 읽었다: %v", n.table)
	}
	// 리포의 고지 문서에 실린 Go의 원문은 이 도구 사슬의 것과 같아야 한다.
	if n.goText != goLicenseOfToolchain(t) {
		t.Fatal("리포의 고지 문서의 Go 원문이 이 도구 사슬의 GOROOT/LICENSE와 다르다")
	}
	if !n.hasSection(module{path: "github.com/BurntSushi/toml", version: "v1.4.0"}) {
		t.Fatal("원문 절을 찾지 못했다")
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
	s := spec{program: "csx", arch: "amd64", version: "v0.1.7", commit: "abc", repo: "x", license: ""}
	err := s.check()
	if err == nil {
		t.Fatal("틀린 옵션을 받아들였다")
	}
	for _, want := range []string{"-program", "-version", "-commit", "-repo", "-license"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%s 를 짚지 않았다: %v", want, err)
		}
	}
	ok := spec{program: "csa", arch: "amd64", version: "0.1.7", commit: strings.Repeat("0", 40), repo: "a/b", license: "Apache-2.0", module: "example.com/m"}
	if err := ok.check(); err != nil || ok.pkgPath != "example.com/m/cmd/csa" {
		t.Fatalf("맞는 옵션을 거절했거나 주 패키지 경로가 다르다: %v, %s", err, ok.pkgPath)
	}
}
