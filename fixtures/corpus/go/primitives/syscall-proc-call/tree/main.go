package main

import "syscall"

func main() {
	var d syscall.DLL
	proc, err := d.FindProc("GetTickCount")
	_ = err
	var p syscall.Proc
	_, _, errno := p.Call(0)
	_ = errno
	_ = proc
}
