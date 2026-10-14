package main

import "net/url"

func main() {
	u, err := url.Parse("https://api.example.com/v1/ping")
	_ = err
	_ = u
	q := url.Values{}
	q.Set("k", "v")
	_ = q.Encode()
}
