package main

import "os/exec"

// The package's unexported error helpers prefixSuffixSaver.Bytes,
// prefixSuffixSaver.Write, wrappedError.Error, and wrappedError.Unwrap
// are inert internals this tree cannot name in code.
func main() {
	p, err := exec.LookPath("sh")
	_ = err
	_ = p
	var exit *exec.ExitError
	var e exec.Error
	_ = exit
	_ = e
	_ = exec.ErrNotFound
}
