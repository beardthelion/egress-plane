package main

import pkg "net/http"

func main() {
    _ = pkg.Dir
    _ = pkg.Dir.Open
    _ = pkg.FS
    _ = pkg.File
    _ = pkg.FileServer
    _ = pkg.FileServerFS
    _ = pkg.FileSystem
    _ = pkg.NewFileTransport
    _ = pkg.NewFileTransportFS
    _ = pkg.ServeContent
    _ = pkg.ServeFile
    _ = pkg.ServeFileFS
    _ = pkg.StripPrefix
}
