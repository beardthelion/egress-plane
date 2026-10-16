package main

import pkg "go/importer"

func main() {
    _ = pkg.Lookup
    _ = pkg.gccgoimports.Import
    _ = pkg.gccgoimports.ImportFrom
    _ = pkg.gcimports.Import
    _ = pkg.gcimports.ImportFrom
}
