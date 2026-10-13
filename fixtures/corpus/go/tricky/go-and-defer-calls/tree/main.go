package main

import "net/http"

func fetch() {
	go http.Get("https://api.example.com/v1/ping")
	defer http.Get("https://api.example.com/v2/ping")
}
