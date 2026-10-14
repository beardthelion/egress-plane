package main

import "os"

func main() {
	var p os.Process
	err := p.Kill()
	_ = err
}
