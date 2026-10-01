package main

import "net/http"

func main() {
	_, _ = http.Get("https://api.example.com/go")
}
