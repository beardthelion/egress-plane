package main

import "os/exec"

func main() {
	var c exec.Cmd
	c.Run()
	c2 := exec.Cmd{Path: "/bin/echo", Args: []string{"echo"}}
	c2.Run()
}
