// sbom은 설치 묶음의 부품 목록(SBOM)을 만들고 검사한다.
//
// 설계 문서의 「발행」 절이 정한 계약을 그대로 밟는다. SPDX 2.3 JSON 문서 하나가
// 묶음 전체를 설명한다. 묶음 Package가 sbom.spdx.json을 뺀 모든 일반 파일을
// CONTAINS하고, 실행 파일은 Go 주 모듈 Package에서 GENERATED_FROM이며, 주 모듈
// Package는 Go 도구 사슬과 의존 모듈 Package 하나하나를 STATIC_LINK한다.
//
// 외부 도구를 내려받지 않는다. 표준 라이브러리 debug/buildinfo로 실행 파일의
// 모듈 목록을 읽고 묶음의 파일을 훑는다. 의존 모듈의 라이선스는 buildinfo에
// 없으므로 THIRD-PARTY-NOTICES.md의 표가 단일 출처다. 그 표와 buildinfo의 모듈
// 집합이 다르면 만들지도 검사를 지나지도 않는다.
//
//	sbom make   -dir <묶음 디렉터리> -program csa -arch amd64 -version 0.1.6 -commit <해시> -repo <소유자/리포> -license Apache-2.0
//	sbom verify -tar <묶음.tar.gz>    -program csa -arch amd64 -version 0.1.6 -commit <해시> -repo <소유자/리포> -license Apache-2.0
//	sbom jsonl  -out <파일.jsonl> <bundle 1> <bundle 2>
//
// make는 묶음 디렉터리에 sbom.spdx.json을 쓴다. verify는 tar를 풀지 않고 읽어
// 묶음의 내용과 sbom.spdx.json과 실행 파일의 buildinfo가 계약대로인지 본다.
// jsonl은 actions/attest가 낸 Sigstore bundle 둘을 한 줄짜리 JSON으로 정규화해
// 한 파일에 담고, 둘이 같은 대상을 가리키며 predicate가 하나씩인지 본다.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// sbomName은 묶음 안에서 SBOM이 놓이는 이름이다. SBOM은 자기 자신을 설명하지
// 않으므로 Package Verification Code의 제외 목록에 이 이름이 들어간다.
const sbomName = "sbom.spdx.json"

const (
	provenanceType = "https://slsa.dev/provenance/v1"
	spdxType       = "https://spdx.dev/Document/v2.3"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "make":
		err = runMake(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "jsonl":
		err = runJSONL(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `사용법: sbom <명령> [옵션]

  make    묶음 디렉터리에 sbom.spdx.json을 쓴다
  verify  묶음 tar.gz의 내용과 SBOM과 실행 파일의 buildinfo를 검사한다
  jsonl   Sigstore bundle 둘을 JSONL 하나로 합치고 검사한다
`)
	os.Exit(2)
}

// spec은 묶음이 무엇이어야 하는지다. 만드는 쪽과 검사하는 쪽이 같은 값을 받는다.
type spec struct {
	program       string
	arch          string
	version       string // 태그의 판. v 없이 0.1.6
	commit        string // 태그가 가리키는 커밋
	repo          string // 소유자/리포
	license       string // 이 리포의 라이선스. SPDX 식별자
	module        string // 주 모듈 경로. 비워 두면 이 프로그램 자신의 모듈이다
	allowModified bool
}

func (s *spec) flags(fs *flag.FlagSet) {
	fs.StringVar(&s.program, "program", "", "프로그램 이름")
	fs.StringVar(&s.arch, "arch", "", "아키텍처")
	fs.StringVar(&s.version, "version", "", "판. v 없이")
	fs.StringVar(&s.commit, "commit", "", "태그가 가리키는 커밋 해시")
	fs.StringVar(&s.repo, "repo", "", "GitHub 리포. 소유자/이름")
	fs.StringVar(&s.license, "license", "", "이 리포의 라이선스. SPDX 식별자")
	fs.StringVar(&s.module, "module", "", "주 모듈 경로. 비워 두면 이 프로그램의 모듈")
	fs.BoolVar(&s.allowModified, "allow-modified", false, "vcs.modified가 참이어도 받는다. 손으로 만들 때만 쓴다. 발행 워크플로는 쓰지 않는다")
}

func (s *spec) check() error {
	var bad []string
	if s.program == "" {
		bad = append(bad, "-program")
	}
	if s.arch == "" {
		bad = append(bad, "-arch")
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$`).MatchString(s.version) {
		bad = append(bad, "-version (예: 0.1.6)")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(s.commit) {
		bad = append(bad, "-commit (40자리 16진수)")
	}
	if !strings.Contains(s.repo, "/") {
		bad = append(bad, "-repo (소유자/이름)")
	}
	if s.license == "" {
		bad = append(bad, "-license")
	}
	if len(bad) > 0 {
		return fmt.Errorf("옵션이 빠졌거나 모양이 틀렸다: %s", strings.Join(bad, ", "))
	}
	if s.module == "" {
		m, err := ownModule()
		if err != nil {
			return err
		}
		s.module = m
	}
	return nil
}

func (s spec) bundle() string { return s.program + "-linux-" + s.arch }
func (s spec) binary() string { return "bin/" + s.program }

// ownModule은 이 프로그램이 든 모듈의 경로다. 검사할 실행 파일의 주 모듈이 이것과
// 같아야 한다. 이 도구는 그 리포 안에 있다.
func ownModule() (string, error) {
	bi, ok := readOwnBuildInfo()
	if !ok || bi.Main.Path == "" {
		return "", errors.New("이 프로그램의 모듈 경로를 알 수 없다. -module로 주라")
	}
	return bi.Main.Path, nil
}

// ---------- 묶음의 내용 ----------

// entry는 묶음 안의 일반 파일 하나다. 이름은 묶음 디렉터리 기준이고 ./ 없이 둔다.
type entry struct {
	name   string
	sha1   string
	sha256 string
	body   []byte // 실행 파일과 SBOM과 고지 문서만 담아 둔다
}

// digest는 바이트를 두 번 재어 돌려준다.
func digest(b []byte) (string, string) {
	s1 := sha1.Sum(b)
	s2 := sha256.Sum256(b)
	return hex.EncodeToString(s1[:]), hex.EncodeToString(s2[:])
}

// readDir는 묶음 디렉터리를 훑는다. 디렉터리와 일반 파일 말고는 거절한다.
func readDir(dir string) ([]entry, error) {
	var out []entry
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			return nil
		case info.Mode().IsRegular():
		default:
			return fmt.Errorf("묶음에 디렉터리와 일반 파일 말고 다른 것이 있다: %s (%s)", rel, info.Mode())
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s1, s2 := digest(b)
		out = append(out, entry{name: filepath.ToSlash(rel), sha1: s1, sha256: s2, body: b})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// readTar는 묶음 tar.gz를 풀지 않고 읽는다. 맨 위 디렉터리 하나가 묶음 이름이어야
// 하고, 그 아래에는 디렉터리와 일반 파일만 있어야 한다. 절대 경로와 ..과 심볼릭
// 링크와 하드 링크와 장치 파일과 FIFO는 거절한다.
func readTar(name, bundle string) ([]entry, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip을 읽지 못했다: %w", err)
	}
	tr := tar.NewReader(gz)
	var out []entry
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar를 읽지 못했다: %w", err)
		}
		clean := path.Clean(h.Name)
		if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(h.Name, "\\") {
			return nil, fmt.Errorf("묶음에 위험한 경로가 있다: %q", h.Name)
		}
		first := strings.SplitN(clean, "/", 2)[0]
		if first != bundle {
			return nil, fmt.Errorf("묶음의 맨 위 디렉터리가 %s이 아니다: %q", bundle, h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("묶음에 디렉터리와 일반 파일 말고 다른 것이 있다: %q (종류 %q)", h.Name, h.Typeflag)
		}
		if clean == bundle {
			return nil, fmt.Errorf("묶음의 맨 위가 디렉터리가 아니다: %q", h.Name)
		}
		rel := strings.TrimPrefix(clean, bundle+"/")
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("tar 안의 파일을 읽지 못했다: %s: %w", rel, err)
		}
		s1, s2 := digest(b)
		out = append(out, entry{name: rel, sha1: s1, sha256: s2, body: b})
	}
	if len(out) == 0 {
		return nil, errors.New("묶음이 비어 있다")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func find(entries []entry, name string) (entry, bool) {
	for _, e := range entries {
		if e.name == name {
			return e, true
		}
	}
	return entry{}, false
}

// ---------- 실행 파일의 buildinfo ----------

// module은 실행 파일에 실제로 들어간 모듈 하나다. Replace가 있었으면 들어간 것이
// path와 version이고 원래 것이 orig다.
type module struct {
	path    string
	version string
	sum     string
	orig    string // "경로@판". 바꾸지 않았으면 빈 값
}

type build struct {
	goVersion string
	mainPath  string
	mainVer   string
	deps      []module
}

// inspect는 실행 파일의 buildinfo를 읽고 계약이 요구하는 것을 본다. 다른 커밋에서
// 만들고 판 문자열만 맞춘 실행 파일은 vcs.revision에서 걸린다.
func inspect(bin []byte, s spec) (build, error) {
	bi, err := buildinfo.Read(bytes.NewReader(bin))
	if err != nil {
		return build{}, fmt.Errorf("실행 파일의 buildinfo를 읽지 못했다: %w", err)
	}
	set := map[string]string{}
	for _, kv := range bi.Settings {
		set[kv.Key] = kv.Value
	}
	var bad []string
	if set["GOOS"] != "linux" {
		bad = append(bad, "GOOS가 linux가 아니다: "+set["GOOS"])
	}
	if set["GOARCH"] != s.arch {
		bad = append(bad, fmt.Sprintf("GOARCH가 묶음 이름과 다르다. 실행 파일 %s, 묶음 %s", set["GOARCH"], s.arch))
	}
	if set["vcs.revision"] != s.commit {
		bad = append(bad, fmt.Sprintf("vcs.revision이 다르다. 실행 파일 %q, 기대 %s", set["vcs.revision"], s.commit))
	}
	if set["vcs.modified"] != "false" && !s.allowModified {
		bad = append(bad, "vcs.modified가 false가 아니다: "+set["vcs.modified"])
	}
	if bi.Main.Path != s.module {
		bad = append(bad, fmt.Sprintf("주 모듈 경로가 다르다. 실행 파일 %s, 기대 %s", bi.Main.Path, s.module))
	}
	if bi.GoVersion == "" {
		bad = append(bad, "Go 도구 사슬의 판이 없다")
	}
	b := build{goVersion: bi.GoVersion, mainPath: bi.Main.Path, mainVer: bi.Main.Version}
	for _, d := range bi.Deps {
		m := module{path: d.Path, version: d.Version, sum: d.Sum}
		if d.Replace != nil {
			// 로컬 경로로 바꾼 모듈은 어디서 온 것인지 남지 않는다.
			if isLocalPath(d.Replace.Path) {
				bad = append(bad, fmt.Sprintf("로컬 경로로 바꾼 모듈이 있다: %s => %s", d.Path, d.Replace.Path))
				continue
			}
			m = module{path: d.Replace.Path, version: d.Replace.Version, sum: d.Replace.Sum, orig: d.Path + "@" + d.Version}
		}
		b.deps = append(b.deps, m)
	}
	sort.Slice(b.deps, func(i, j int) bool { return b.deps[i].path < b.deps[j].path })
	if len(bad) > 0 {
		return build{}, fmt.Errorf("실행 파일의 buildinfo가 계약에 어긋난다:\n  %s", strings.Join(bad, "\n  "))
	}
	return b, nil
}

// isLocalPath는 모듈 교체가 파일 경로인지 본다. 모듈 경로는 첫 조각에 점이 있다.
func isLocalPath(p string) bool {
	if strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") || p == "." || p == ".." {
		return true
	}
	first := strings.SplitN(p, "/", 2)[0]
	return !strings.Contains(first, ".")
}

// ---------- 고지 문서의 표 ----------

// licenseIDs는 고지 문서가 쓰는 라이선스 이름과 SPDX 식별자다. 여기 없는 이름은
// 거절한다. 모르는 라이선스를 조용히 지나치지 않으려는 것이다.
var licenseIDs = map[string]string{
	"MIT":                "MIT",
	"BSD 3-Clause":       "BSD-3-Clause",
	"BSD 2-Clause":       "BSD-2-Clause",
	"Apache License 2.0": "Apache-2.0",
	"ISC":                "ISC",
	"MPL 2.0":            "MPL-2.0",
}

// noticeRow는 고지 문서의 표 한 줄이다. | `경로` | 판 | 라이선스 | 모양이다.
var noticeRow = regexp.MustCompile("^\\| `([^`]+)` \\| ([^|]+?) \\| ([^|]+?) \\|$")

// readNotices는 THIRD-PARTY-NOTICES.md의 표를 읽어 모듈마다 라이선스를 돌려준다.
func readNotices(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		m := noticeRow.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		id, ok := licenseIDs[strings.TrimSpace(m[3])]
		if !ok {
			return nil, fmt.Errorf("고지 문서의 라이선스 이름을 모른다: %q (%s)", m[3], m[1])
		}
		out[m[1]+"@"+strings.TrimSpace(m[2])] = id
	}
	if len(out) == 0 {
		return nil, errors.New("고지 문서에서 표를 찾지 못했다")
	}
	return out, nil
}

// matchNotices는 buildinfo의 모듈 집합과 고지 문서의 표가 같은지 본다. 표가 단일
// 출처이므로 어느 쪽에만 있는 것이 있으면 발행하지 않는다.
func matchNotices(deps []module, notices map[string]string) (map[string]string, error) {
	var bad []string
	seen := map[string]bool{}
	lic := map[string]string{}
	for _, d := range deps {
		key := d.path + "@" + d.version
		id, ok := notices[key]
		if !ok {
			bad = append(bad, "실행 파일에는 있는데 고지 문서의 표에 없다: "+key)
			continue
		}
		seen[key] = true
		lic[key] = id
	}
	for key := range notices {
		if !seen[key] {
			bad = append(bad, "고지 문서의 표에는 있는데 실행 파일에 없다: "+key)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return nil, fmt.Errorf("의존 모듈과 고지 문서가 다르다:\n  %s", strings.Join(bad, "\n  "))
	}
	return lic, nil
}

// ---------- SPDX 문서 ----------

type checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type verificationCode struct {
	Value    string   `json:"packageVerificationCodeValue"`
	Excluded []string `json:"packageVerificationCodeExcludedFiles,omitempty"`
}

type externalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type pkg struct {
	Name             string            `json:"name"`
	ID               string            `json:"SPDXID"`
	Version          string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	VerificationCode *verificationCode `json:"packageVerificationCode,omitempty"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	Purpose          string            `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs     []externalRef     `json:"externalRefs,omitempty"`
	Comment          string            `json:"comment,omitempty"`
	HasFiles         []string          `json:"hasFiles,omitempty"`
}

type file struct {
	Name             string     `json:"fileName"`
	ID               string     `json:"SPDXID"`
	Types            []string   `json:"fileTypes,omitempty"`
	Checksums        []checksum `json:"checksums"`
	LicenseConcluded string     `json:"licenseConcluded"`
	CopyrightText    string     `json:"copyrightText"`
}

type relationship struct {
	From string `json:"spdxElementId"`
	Type string `json:"relationshipType"`
	To   string `json:"relatedSpdxElement"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	ID                string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []pkg          `json:"packages"`
	Files             []file         `json:"files"`
	Relationships     []relationship `json:"relationships"`
	Describes         []string       `json:"documentDescribes,omitempty"`
}

const (
	idDocument = "SPDXRef-DOCUMENT"
	idBundle   = "SPDXRef-Package-bundle"
	idMain     = "SPDXRef-Package-main"
	idStdlib   = "SPDXRef-Package-go-stdlib"
)

// spdxID는 이름을 SPDX 식별자에 쓸 수 있는 글자로 바꾼다. 글자와 숫자와 점과
// 붙임표만 허용된다.
func spdxID(prefix, name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return "SPDXRef-" + prefix + "-" + b.String()
}

func fileTypes(name string) []string {
	switch {
	case strings.HasPrefix(name, "bin/"):
		return []string{"BINARY"}
	case strings.HasSuffix(name, ".sh"):
		return []string{"SOURCE"}
	case strings.HasSuffix(name, ".md"):
		return []string{"DOCUMENTATION"}
	default:
		return []string{"TEXT"}
	}
}

// verificationCodeOf는 SPDX가 정한 대로 계산한다. 포함하는 파일들의 SHA-1을 정렬해
// 이어 붙이고 그것의 SHA-1이다.
func verificationCodeOf(entries []entry) string {
	var sums []string
	for _, e := range entries {
		if e.name != sbomName {
			sums = append(sums, e.sha1)
		}
	}
	sort.Strings(sums)
	h := sha1.Sum([]byte(strings.Join(sums, "")))
	return hex.EncodeToString(h[:])
}

func purlGo(path, version string) string {
	return "pkg:golang/" + path + "@" + version
}

// compose는 묶음의 내용과 buildinfo와 라이선스 표로 SPDX 문서를 만든다.
func compose(s spec, entries []entry, b build, lic map[string]string, created time.Time) document {
	bundle := s.bundle()
	doc := document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		ID:                idDocument,
		Name:              bundle + "-" + s.version,
		DocumentNamespace: fmt.Sprintf("https://github.com/%s/releases/download/v%s/%s.spdx.json", s.repo, s.version, bundle),
		CreationInfo: creationInfo{
			Created:  created.UTC().Format("2006-01-02T15:04:05Z"),
			Creators: []string{"Tool: " + strings.SplitN(s.repo, "/", 2)[1] + "-sbom-" + s.version},
		},
		Describes: []string{idBundle},
	}
	var files []file
	var fileIDs []string
	for _, e := range entries {
		if e.name == sbomName {
			continue
		}
		id := spdxID("File", e.name)
		fileIDs = append(fileIDs, id)
		files = append(files, file{
			Name:  "./" + e.name,
			ID:    id,
			Types: fileTypes(e.name),
			Checksums: []checksum{
				{Algorithm: "SHA1", Value: e.sha1},
				{Algorithm: "SHA256", Value: e.sha256},
			},
			LicenseConcluded: s.license,
			CopyrightText:    "NOASSERTION",
		})
	}
	doc.Files = files
	doc.Packages = append(doc.Packages, pkg{
		Name:             bundle,
		ID:               idBundle,
		Version:          s.version,
		DownloadLocation: fmt.Sprintf("https://github.com/%s/releases/download/v%s/%s.tar.gz", s.repo, s.version, bundle),
		FilesAnalyzed:    true,
		VerificationCode: &verificationCode{Value: verificationCodeOf(entries), Excluded: []string{"./" + sbomName}},
		LicenseConcluded: s.license,
		LicenseDeclared:  s.license,
		CopyrightText:    "NOASSERTION",
		Purpose:          "INSTALL",
		HasFiles:         fileIDs,
	})
	main := pkg{
		Name:             b.mainPath,
		ID:               idMain,
		Version:          "v" + s.version,
		DownloadLocation: fmt.Sprintf("git+https://github.com/%s@v%s", s.repo, s.version),
		FilesAnalyzed:    false,
		LicenseConcluded: s.license,
		LicenseDeclared:  s.license,
		CopyrightText:    "NOASSERTION",
		Purpose:          "APPLICATION",
		ExternalRefs:     []externalRef{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: purlGo(b.mainPath, "v"+s.version)}},
		Comment:          "vcs.revision " + s.commit,
	}
	if b.mainVer != "" && b.mainVer != "(devel)" {
		main.Comment += ". buildinfo가 말하는 주 모듈의 판 " + b.mainVer
	}
	doc.Packages = append(doc.Packages, main)
	goVer := strings.TrimPrefix(b.goVersion, "go")
	doc.Packages = append(doc.Packages, pkg{
		Name:             "stdlib",
		ID:               idStdlib,
		Version:          goVer,
		DownloadLocation: "https://go.dev/dl/",
		FilesAnalyzed:    false,
		LicenseConcluded: "BSD-3-Clause",
		LicenseDeclared:  "BSD-3-Clause",
		CopyrightText:    "NOASSERTION",
		Purpose:          "LIBRARY",
		ExternalRefs:     []externalRef{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: purlGo("stdlib", goVer)}},
		Comment:          "Go 도구 사슬 " + b.goVersion,
	})
	rel := []relationship{
		{From: idDocument, Type: "DESCRIBES", To: idBundle},
	}
	for _, id := range fileIDs {
		rel = append(rel, relationship{From: idBundle, Type: "CONTAINS", To: id})
	}
	rel = append(rel, relationship{From: spdxID("File", s.binary()), Type: "GENERATED_FROM", To: idMain})
	rel = append(rel, relationship{From: idMain, Type: "STATIC_LINK", To: idStdlib})
	for _, d := range b.deps {
		id := spdxID("Package", d.path)
		p := pkg{
			Name:             d.path,
			ID:               id,
			Version:          d.version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: lic[d.path+"@"+d.version],
			LicenseDeclared:  "NOASSERTION",
			CopyrightText:    "NOASSERTION",
			Purpose:          "LIBRARY",
			ExternalRefs:     []externalRef{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: purlGo(d.path, d.version)}},
			// go.sum의 h1: 해시는 SPDX의 SHA-256이 아니다. checksums에 넣지 않고 원문 그대로 둔다.
			Comment: "go.sum " + d.sum,
		}
		if d.orig != "" {
			p.Comment += ". " + d.orig + " 을 이것으로 바꿔 넣었다"
		}
		doc.Packages = append(doc.Packages, p)
		rel = append(rel, relationship{From: idMain, Type: "STATIC_LINK", To: id})
	}
	doc.Relationships = rel
	return doc
}

// ---------- make ----------

func runMake(args []string) error {
	fs := flag.NewFlagSet("make", flag.ExitOnError)
	var s spec
	s.flags(fs)
	dir := fs.String("dir", "", "묶음 디렉터리")
	notices := fs.String("notices", "", "고지 문서. 비워 두면 묶음 안의 THIRD-PARTY-NOTICES.md")
	fs.Parse(args)
	if err := s.check(); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir이 빠졌다")
	}
	// 앞서 만든 SBOM이 있으면 치운다. 자기 자신을 설명하지 않으므로 훑기 전에 없애야 한다.
	os.Remove(filepath.Join(*dir, sbomName))
	entries, err := readDir(*dir)
	if err != nil {
		return err
	}
	bin, ok := find(entries, s.binary())
	if !ok {
		return fmt.Errorf("묶음에 실행 파일이 없다: %s", s.binary())
	}
	b, err := inspect(bin.body, s)
	if err != nil {
		return err
	}
	var noticeBody []byte
	if *notices != "" {
		noticeBody, err = os.ReadFile(*notices)
		if err != nil {
			return err
		}
	} else {
		n, ok := find(entries, "THIRD-PARTY-NOTICES.md")
		if !ok {
			return errors.New("묶음에 THIRD-PARTY-NOTICES.md가 없다")
		}
		noticeBody = n.body
	}
	table, err := readNotices(noticeBody)
	if err != nil {
		return err
	}
	lic, err := matchNotices(b.deps, table)
	if err != nil {
		return err
	}
	doc := compose(s, entries, b, lic, time.Now())
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(filepath.Join(*dir, sbomName), out, 0o644); err != nil {
		return err
	}
	fmt.Printf("SBOM을 썼습니다. 파일 %d개, 의존 모듈 %d개, Go %s: %s\n", len(entries), len(b.deps), b.goVersion, filepath.Join(*dir, sbomName))
	return nil
}

// ---------- verify ----------

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var s spec
	s.flags(fs)
	tarPath := fs.String("tar", "", "묶음 tar.gz")
	copyPath := fs.String("copy", "", "릴리스에 따로 붙일 SBOM 사본. 주면 묶음 안의 것과 바이트가 같은지 본다")
	fs.Parse(args)
	if err := s.check(); err != nil {
		return err
	}
	if *tarPath == "" {
		return errors.New("-tar가 빠졌다")
	}
	entries, err := readTar(*tarPath, s.bundle())
	if err != nil {
		return err
	}
	bin, ok := find(entries, s.binary())
	if !ok {
		return fmt.Errorf("묶음에 실행 파일이 없다: %s", s.binary())
	}
	b, err := inspect(bin.body, s)
	if err != nil {
		return err
	}
	sbom, ok := find(entries, sbomName)
	if !ok {
		return fmt.Errorf("묶음에 %s이 없다", sbomName)
	}
	if *copyPath != "" {
		c, err := os.ReadFile(*copyPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(c, sbom.body) {
			return fmt.Errorf("SBOM 사본이 묶음 안의 것과 다르다: %s", *copyPath)
		}
	}
	notice, ok := find(entries, "THIRD-PARTY-NOTICES.md")
	if !ok {
		return errors.New("묶음에 THIRD-PARTY-NOTICES.md가 없다")
	}
	table, err := readNotices(notice.body)
	if err != nil {
		return err
	}
	lic, err := matchNotices(b.deps, table)
	if err != nil {
		return err
	}
	var doc document
	if err := json.Unmarshal(sbom.body, &doc); err != nil {
		return fmt.Errorf("%s을 읽지 못했다: %w", sbomName, err)
	}
	if err := checkDoc(doc, s, entries, b, lic); err != nil {
		return err
	}
	fmt.Printf("묶음이 계약대로입니다. 파일 %d개, 의존 모듈 %d개, Go %s, 커밋 %s: %s\n", len(entries)-1, len(b.deps), b.goVersion, s.commit[:7], *tarPath)
	return nil
}

// checkDoc은 SBOM이 묶음의 내용과 buildinfo와 맞는지 본다. 개수가 아니라 내용을 본다.
func checkDoc(doc document, s spec, entries []entry, b build, lic map[string]string) error {
	var bad []string
	note := func(f string, a ...any) { bad = append(bad, fmt.Sprintf(f, a...)) }
	if doc.SPDXVersion != "SPDX-2.3" {
		note("spdxVersion이 SPDX-2.3이 아니다: %s", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		note("dataLicense가 CC0-1.0이 아니다: %s", doc.DataLicense)
	}
	if doc.Name != s.bundle()+"-"+s.version {
		note("문서 이름이 묶음과 판을 말하지 않는다: %s", doc.Name)
	}
	if len(doc.Describes) != 1 || doc.Describes[0] != idBundle {
		note("문서가 묶음 Package를 DESCRIBES하지 않는다")
	}
	pk := map[string]pkg{}
	for _, p := range doc.Packages {
		pk[p.ID] = p
	}
	bundle, ok := pk[idBundle]
	switch {
	case !ok:
		note("묶음 Package가 없다")
	case !bundle.FilesAnalyzed:
		note("묶음 Package의 filesAnalyzed가 참이 아니다")
	case bundle.VerificationCode == nil:
		note("묶음 Package에 packageVerificationCode가 없다")
	default:
		if bundle.VerificationCode.Value != verificationCodeOf(entries) {
			note("packageVerificationCode가 묶음의 파일과 맞지 않는다")
		}
		if len(bundle.VerificationCode.Excluded) != 1 || bundle.VerificationCode.Excluded[0] != "./"+sbomName {
			note("packageVerificationCodeExcludedFiles가 ./%s 하나가 아니다", sbomName)
		}
		if bundle.Name != s.bundle() || bundle.Version != s.version {
			note("묶음 Package의 이름이나 판이 다르다: %s %s", bundle.Name, bundle.Version)
		}
	}
	main, ok := pk[idMain]
	switch {
	case !ok:
		note("주 모듈 Package가 없다")
	default:
		if main.Name != b.mainPath {
			note("주 모듈 경로가 다르다. SBOM %s, buildinfo %s", main.Name, b.mainPath)
		}
		if main.Version != "v"+s.version {
			note("주 모듈의 판이 태그와 다르다. SBOM %s, 태그 v%s", main.Version, s.version)
		}
		want := purlGo(b.mainPath, "v"+s.version)
		if len(main.ExternalRefs) != 1 || main.ExternalRefs[0].Locator != want {
			note("주 모듈의 purl이 다르다: 기대 %s", want)
		}
	}
	std, ok := pk[idStdlib]
	if !ok || std.Version != strings.TrimPrefix(b.goVersion, "go") {
		note("Go 도구 사슬 정보가 없거나 buildinfo와 다르다")
	}
	// 의존 모듈 집합
	rels := map[string]map[string]bool{} // type → from|to
	for _, r := range doc.Relationships {
		if rels[r.Type] == nil {
			rels[r.Type] = map[string]bool{}
		}
		rels[r.Type][r.From+"|"+r.To] = true
	}
	depIDs := map[string]bool{}
	for _, d := range b.deps {
		id := spdxID("Package", d.path)
		depIDs[id] = true
		p, ok := pk[id]
		if !ok {
			note("의존 모듈이 SBOM에 없다: %s@%s", d.path, d.version)
			continue
		}
		if p.Name != d.path || p.Version != d.version {
			note("의존 모듈의 경로나 판이 다르다: SBOM %s@%s, buildinfo %s@%s", p.Name, p.Version, d.path, d.version)
		}
		if p.LicenseConcluded != lic[d.path+"@"+d.version] {
			note("의존 모듈의 라이선스가 고지 문서와 다르다: %s", d.path)
		}
		if !strings.Contains(p.Comment, "go.sum "+d.sum) {
			note("의존 모듈의 go.sum 해시가 주석에 없다: %s", d.path)
		}
		if !rels["STATIC_LINK"][idMain+"|"+id] {
			note("주 모듈이 의존 모듈을 STATIC_LINK하지 않는다: %s", d.path)
		}
	}
	for id, p := range pk {
		if strings.HasPrefix(id, "SPDXRef-Package-") && id != idBundle && id != idMain && id != idStdlib && !depIDs[id] {
			note("buildinfo에 없는 모듈이 SBOM에 있다: %s", p.Name)
		}
	}
	if !rels["STATIC_LINK"][idMain+"|"+idStdlib] {
		note("주 모듈이 Go 도구 사슬을 STATIC_LINK하지 않는다")
	}
	if !rels["GENERATED_FROM"][spdxID("File", s.binary())+"|"+idMain] {
		note("실행 파일이 주 모듈에서 GENERATED_FROM이 아니다")
	}
	// 파일 집합과 해시
	fl := map[string]file{}
	for _, f := range doc.Files {
		fl[strings.TrimPrefix(f.Name, "./")] = f
	}
	for _, e := range entries {
		if e.name == sbomName {
			continue
		}
		f, ok := fl[e.name]
		if !ok {
			note("묶음의 파일이 SBOM에 없다: %s", e.name)
			continue
		}
		sums := map[string]string{}
		for _, c := range f.Checksums {
			sums[c.Algorithm] = c.Value
		}
		if sums["SHA1"] != e.sha1 || sums["SHA256"] != e.sha256 {
			note("파일의 해시가 다르다: %s", e.name)
		}
		if !rels["CONTAINS"][idBundle+"|"+f.ID] {
			note("묶음 Package가 파일을 CONTAINS하지 않는다: %s", e.name)
		}
		delete(fl, e.name)
	}
	for name := range fl {
		note("SBOM에는 있는데 묶음에 없는 파일이 있다: %s", name)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("SBOM이 계약에 어긋난다:\n  %s", strings.Join(bad, "\n  "))
	}
	return nil
}

// ---------- jsonl ----------

// statement는 in-toto 문장이다. Sigstore bundle의 dsseEnvelope.payload에 base64로
// 들어 있다.
type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// runJSONL은 bundle 둘을 한 줄짜리 JSON으로 정규화해 한 파일에 담는다. 그냥 이어
// 붙이지 않는다. bundle 파일은 여러 줄일 수 있다. 두 줄이 같은 대상 이름과
// sha256을 가리키고 predicate가 출처 증명 하나와 SBOM 증명 하나인지 본다.
func runJSONL(args []string) error {
	fs := flag.NewFlagSet("jsonl", flag.ExitOnError)
	out := fs.String("out", "", "쓸 JSONL 파일")
	fs.Parse(args)
	if *out == "" || fs.NArg() != 2 {
		return errors.New("사용법: sbom jsonl -out <파일.jsonl> <bundle 1> <bundle 2>")
	}
	var lines [][]byte
	var subject string
	seen := map[string]bool{}
	for i, name := range fs.Args() {
		raw, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("bundle을 읽지 못했다: %s: %w", name, err)
		}
		line, err := json.Marshal(v)
		if err != nil {
			return err
		}
		st, err := statementOf(v)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] == "" {
			return fmt.Errorf("bundle의 대상이 하나가 아니거나 sha256이 없다: %s", name)
		}
		key := st.Subject[0].Name + " " + st.Subject[0].Digest["sha256"]
		if i == 0 {
			subject = key
		} else if key != subject {
			return fmt.Errorf("두 bundle의 대상이 다르다: %q, %q", subject, key)
		}
		if st.PredicateType != provenanceType && st.PredicateType != spdxType {
			return fmt.Errorf("모르는 predicate다: %s", st.PredicateType)
		}
		if seen[st.PredicateType] {
			return fmt.Errorf("같은 predicate가 둘이다: %s", st.PredicateType)
		}
		seen[st.PredicateType] = true
		lines = append(lines, line)
	}
	if !seen[provenanceType] || !seen[spdxType] {
		return errors.New("출처 증명과 SBOM 증명이 하나씩 있어야 한다")
	}
	body := append(bytes.Join(lines, []byte("\n")), '\n')
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("증명 묶음을 썼습니다. 대상 %s: %s\n", subject, *out)
	return nil
}

func statementOf(bundle map[string]any) (statement, error) {
	env, _ := bundle["dsseEnvelope"].(map[string]any)
	payload, _ := env["payload"].(string)
	if payload == "" {
		return statement{}, errors.New("bundle에 dsseEnvelope.payload가 없다")
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return statement{}, fmt.Errorf("payload를 풀지 못했다: %w", err)
	}
	var st statement
	if err := json.Unmarshal(raw, &st); err != nil {
		return statement{}, fmt.Errorf("in-toto 문장을 읽지 못했다: %w", err)
	}
	return st, nil
}
