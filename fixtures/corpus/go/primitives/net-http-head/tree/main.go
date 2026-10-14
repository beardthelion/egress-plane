package main

import "net/http"

func main() {
	r, err := http.Head("https://api.example.com/v1/ping")
	_ = err
	_ = r
}
