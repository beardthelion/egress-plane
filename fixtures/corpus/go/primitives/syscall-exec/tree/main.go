package main

import "syscall"

func main() {
	_ = syscall.Exec("/bin/curl", []string{"curl", "https://api.example.com"}, nil)
}
