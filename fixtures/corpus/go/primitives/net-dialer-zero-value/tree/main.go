package main

import "net"

func main() {
	var d net.Dialer
	d.Dial("tcp", "dial.example.com:443")
	e := net.Dialer{}
	e.Dial("tcp", "dial2.example.com:443")
}
