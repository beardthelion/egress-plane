package main

import "golang.org/x/net/proxy"

func main() {
	d, err := proxy.SOCKS5("tcp", "proxy.example.com:1080", nil, nil)
	_ = err
	_ = d
}
