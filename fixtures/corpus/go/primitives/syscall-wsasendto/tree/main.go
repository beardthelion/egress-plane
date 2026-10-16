package main

import "syscall"

func main() {
	var b syscall.WSASendto
	syscall.WSASendTo(0, &b, nil, nil, 0)
}
