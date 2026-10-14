package main

import "os"

func main() {
	r, w, err := os.Pipe()
	_ = err
	_, _ = r, w
	var _ = os.Pipe2
}
