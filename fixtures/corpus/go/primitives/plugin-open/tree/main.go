package main

import "plugin"

func main() {
	p, err := plugin.Open("./libexample.so")
	_ = err
	_ = p
}
