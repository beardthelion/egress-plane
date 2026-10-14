package main

import "os/exec"

// The package's unexported error helpers prefixSuffixSaver.Bytes,
// prefixSuffixSaver.Write, wrappedError.Error, and wrappedError.Unwrap
// stay inert.
func main() {
	p, err := exec.LookPath("sh")
	_ = err
	_ = p
	var exit *exec.ExitError
	var e exec.Error
	_ = exit
	_ = e
	_ = exec.ErrNotFound
	_ = exec.Cmd.String
	_ = exec.Error.Error
	_ = exec.Error.Unwrap
	_ = exec.ExitError.Error
	_ = exec.prefixSuffixSaver.Bytes
	_ = exec.prefixSuffixSaver.Write
	_ = exec.wrappedError.Error
	_ = exec.wrappedError.Unwrap
}
