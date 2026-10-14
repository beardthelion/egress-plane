package main

import "os/exec"

func main() {
	var c exec.Cmd
	err := c.Run()
	_ = err
}
