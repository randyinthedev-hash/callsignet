// hello는 sbom 도구의 시험이 만드는 실행 파일이다. 의존 모듈이 하나 있어야
// 고지 문서의 표와 견주는 길이 시험된다.
package main

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

func main() {
	var v struct{ A int }
	_, err := toml.Decode("a = 1", &v)
	fmt.Println(v.A, err)
}
