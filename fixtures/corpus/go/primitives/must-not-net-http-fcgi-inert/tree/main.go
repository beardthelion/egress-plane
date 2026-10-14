package main

import "net/http/fcgi"

// The unexported stream internals bufWriter, conn, and streamWriter
// carry Close and Write members that stay inert.
func main() {
	var _ = fcgi.ErrConnClosed
	var _ = fcgi.ErrRequestAborted
	var e fcgi.ProcessEnv
	_ = e
	_ = fcgi.response.Write
	_ = fcgi.bufWriter.Close
	_ = fcgi.conn.Close
	_ = fcgi.streamWriter.Close
	_ = fcgi.streamWriter.Write
}
