package main

import "unsafe"

func main() {
	x := 0
	p := unsafe.Pointer(&x)
	_ = p
}
