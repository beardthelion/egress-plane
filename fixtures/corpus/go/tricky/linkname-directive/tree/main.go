package main

//go:linkname nanotime runtime.nanotime
func nanotime() int64 {
	return 0
}

// go:linkname fake runtime.fake

func main() {}
