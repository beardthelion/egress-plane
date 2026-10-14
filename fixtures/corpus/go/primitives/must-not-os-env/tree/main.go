package main

import "os"

func main() {
	_ = os.Getenv("HOME")
	_, _ = os.LookupEnv("HOME")
	_ = os.Environ()
	_ = os.ExpandEnv("$HOME")
	_ = os.Expand("$X", func(s string) string { return s })
	_ = os.Setenv("K", "v")
	_ = os.Unsetenv("K")
	os.Clearenv()
}
