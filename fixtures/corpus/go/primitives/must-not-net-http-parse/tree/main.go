package main

import pkg "net/http"

func main() {
    _ = pkg.CanonicalHeaderKey
    _ = pkg.DetectContentType
    _ = pkg.ParseCookie
    _ = pkg.ParseHTTPVersion
    _ = pkg.ParseSetCookie
    _ = pkg.ParseTime
    _ = pkg.ProxyFromEnvironment
    _ = pkg.ProxyURL
    _ = pkg.ReadRequest
    _ = pkg.ReadResponse
    _ = pkg.Request.FormValue
    _ = pkg.Request.ParseMultipartForm
    _ = pkg.Request.PostFormValue
}
