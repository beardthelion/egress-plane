package main

import "os"

func main() {
	p, err := os.FindProcess(4242)
	_ = err
	_ = p
}
