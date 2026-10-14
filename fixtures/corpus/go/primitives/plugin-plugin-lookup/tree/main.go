package main

import "plugin"

func main() {
	var p plugin.Plugin
	s, err := p.Lookup("Serve")
	_ = err
	_ = s
}
