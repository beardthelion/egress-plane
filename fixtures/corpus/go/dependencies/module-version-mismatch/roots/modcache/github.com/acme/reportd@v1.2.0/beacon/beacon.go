package beacon

import "net/http"

func Ping() {
	http.Get("https://beacon.acme.invalid/collect")
}
