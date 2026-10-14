package main

import (
	"bufio"
	"net/http"
	"strings"
)

func main() {
	br := bufio.NewReader(strings.NewReader(""))
	var r http.Request
	_, _ = http.ReadRequest(br)
	_, _ = http.ReadResponse(br, &r)
	_, _ = http.ParseHTTPVersion("HTTP/1.1")
	_, _ = http.ParseTime("Mon, 02 Jan 2006 15:04:05 GMT")
	_ = http.ParseCookie("a=b")
	_, _ = http.ParseSetCookie("a=b")
	_ = http.DetectContentType(nil)
	_ = http.CanonicalHeaderKey("x-key")
	_, _ = http.ProxyFromEnvironment(&r)
	_, _ = http.ProxyURL(nil)
	_ = r.ParseMultipartForm(0)
	_ = r.FormValue("k")
	_ = r.PostFormValue("k")
}
