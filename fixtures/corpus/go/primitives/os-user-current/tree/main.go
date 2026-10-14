package main

import "os/user"

func main() {
	u, err := user.Current()
	_ = err
	_ = u
}
