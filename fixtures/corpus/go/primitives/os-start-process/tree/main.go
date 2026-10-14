package main

import "os"

func main() {
	p, err := os.StartProcess("/bin/curl", []string{"curl", "https://api.example.com"}, nil)
	_ = err
	_ = p
}
