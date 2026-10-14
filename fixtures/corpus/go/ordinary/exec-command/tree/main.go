package main

import "os/exec"

func main() {
	out, err := exec.Command("curl", "https://api.example.com/v1/ping").Output()
	_ = err
	_ = out
}
