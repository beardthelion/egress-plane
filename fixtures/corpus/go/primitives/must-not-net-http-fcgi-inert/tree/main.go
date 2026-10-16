package main

import pkg "net/http/fcgi"

func main() {
    _ = pkg.ErrConnClosed
    _ = pkg.ErrRequestAborted
    _ = pkg.ProcessEnv
    _ = pkg.bufWriter.Close
    _ = pkg.conn.Close
    _ = pkg.response.Example
    _ = pkg.streamWriter.Close
    _ = pkg.streamWriter.Write
}
