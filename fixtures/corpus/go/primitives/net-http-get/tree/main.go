package main

import "net/http"

func main() {
	resp, err := http.Get("https://api.example.com/v1/ping")
	_ = err
	_ = resp
}
