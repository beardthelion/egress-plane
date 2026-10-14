package main

import "syscall"

func main() {
	syscall.Syscall(39, 0, 0, 0)
}
