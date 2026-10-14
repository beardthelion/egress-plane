package main

import "os"

func main() {
	var f os.File
	rc, err := f.SyscallConn()
	_ = err
	_ = rc
}
