// other는 sbom 도구의 시험이 만드는 또 하나의 실행 파일이다. 같은 모듈의 다른
// 프로그램을 csa의 자리에 넣었을 때 주 패키지 경로에서 걸리는지 보는 데 쓴다.
package main

import "fmt"

func main() {
	fmt.Println("other")
}
