package main

import "runtime/debug"

// readOwnBuildInfo는 이 프로그램 자신의 buildinfo다. 시험이 바꿔 끼운다.
var readOwnBuildInfo = debug.ReadBuildInfo
