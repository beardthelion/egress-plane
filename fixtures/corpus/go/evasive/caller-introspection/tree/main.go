package main

import "runtime"

func probe() {
	runtime.Caller(0)
}
