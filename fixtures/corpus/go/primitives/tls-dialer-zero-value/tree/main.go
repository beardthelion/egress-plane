package main

import "crypto/tls"

func main() {
	var d tls.Dialer
	d.Dial("tcp", "tls.example.com:443")
	d2 := tls.Dialer{}
	d2.Dial("tcp", "tls.example.org:443")
}
