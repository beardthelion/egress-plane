package main

import "runtime/debug"

func main() {
	b := debug.Stack()
	_ = b
}
