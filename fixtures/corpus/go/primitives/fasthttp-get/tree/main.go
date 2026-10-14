package main

import "github.com/valyala/fasthttp"

func main() {
	_, body, err := fasthttp.Get(nil, "https://api.example.com/v1/ping")
	_ = err
	_ = body
}
