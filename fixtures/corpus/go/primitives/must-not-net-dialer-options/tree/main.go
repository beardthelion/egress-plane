package main

import "net"

func main() {
	var d net.Dialer
	_ = d.MultipathTCP
	_ = d.SetMultipathTCP
	var l net.ListenConfig
	_ = l.MultipathTCP
	_ = l.SetMultipathTCP
}
