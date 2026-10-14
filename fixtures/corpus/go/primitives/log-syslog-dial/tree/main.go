package main

import "log/syslog"

func main() {
	w, err := syslog.Dial("udp", "log.example.com:514", syslog.LOG_INFO, "app")
	_ = err
	_ = w
}
