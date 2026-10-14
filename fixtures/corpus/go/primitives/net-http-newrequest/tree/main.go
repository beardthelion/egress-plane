package main

import "net/http"

func main() {
	req, err := http.NewRequest("GET", "https://api.example.com/v1/ping", nil)
	_ = err
	_ = req
}
