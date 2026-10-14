package main

import "os/exec"

func main() {
	cmd := exec.Command("curl", "https://api.example.com/v1/ping")
	_ = cmd.Run()
}
