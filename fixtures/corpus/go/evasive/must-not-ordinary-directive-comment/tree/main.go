package main

import _ "unsafe"

// go:linkname runtimeNow runtime.nanotime
func runtimeNow() int64

func probe() {
	runtimeNow()
}
