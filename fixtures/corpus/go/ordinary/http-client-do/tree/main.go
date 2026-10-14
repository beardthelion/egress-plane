package main

import "net/http"

func main() {
	var c http.Client
	req, err := http.NewRequest("GET", "https://api.example.com/v1/ping", nil)
	_ = err
	resp, err := c.Do(req)
	_ = err
	_ = resp
}
