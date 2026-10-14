package main

import "go/build"

func main() {
	p, err := build.Import("fmt", ".", 0)
	_ = err
	_ = p
}
