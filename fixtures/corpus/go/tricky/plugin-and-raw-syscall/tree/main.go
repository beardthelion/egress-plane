package main

import (
	"plugin"
	"syscall"
)

func main() {
	p, _ := plugin.Open("x.so")
	_ = p
	syscall.Syscall(0, 0, 0, 0)
}
