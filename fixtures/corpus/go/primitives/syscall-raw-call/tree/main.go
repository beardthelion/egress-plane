package main

import "syscall"

func main() {
	syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
}
