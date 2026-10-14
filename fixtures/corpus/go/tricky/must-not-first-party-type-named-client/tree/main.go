package main

import "net/http"

type Client struct{}

func (c *Client) Get(u string) {}

func main() {
	var c Client
	c.Get("https://internal.example.com")
	_ = http.MethodGet
}
