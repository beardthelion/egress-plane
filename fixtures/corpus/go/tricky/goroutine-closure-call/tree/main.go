package main

import "net/http"

func main() {
	go func() {
		http.Get("https://api.example.com/v1/ping")
	}()
}
