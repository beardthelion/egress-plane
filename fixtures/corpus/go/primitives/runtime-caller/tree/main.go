package main

import "runtime"

func main() {
	_, file, line, ok := runtime.Caller(0)
	_, _, _ = file, line, ok
}
