package main

import "golang.org/x/crypto/ssh"

func main() {
	c, err := ssh.Dial("tcp", "ssh.example.com:22", nil)
	_ = err
	_ = c
}
