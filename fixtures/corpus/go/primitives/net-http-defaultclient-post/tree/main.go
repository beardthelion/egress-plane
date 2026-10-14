package main

import "net/http"

func main() {
	r, err := http.DefaultClient.Post("https://api.example.com/v1/items", "text/plain", nil)
	_ = err
	_ = r
}
