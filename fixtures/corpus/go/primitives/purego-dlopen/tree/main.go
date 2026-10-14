package main

import "github.com/ebitengine/purego"

func main() {
	h, err := purego.Dlopen("libexample.so", purego.RTLD_NOW)
	_ = err
	_ = h
}
