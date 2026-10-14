package testdata

import "net"

func Connect() {
	conn, err := net.Dial("tcp", "testdata.example.com:443")
	_ = err
	_ = conn
}
