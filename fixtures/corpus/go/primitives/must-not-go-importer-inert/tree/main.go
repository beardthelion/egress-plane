package main

import "go/importer"

// The gcimports and gccgoimports importer backends' Import and
// ImportFrom members stay inert.
func main() {
	var _ = importer.Lookup
}
