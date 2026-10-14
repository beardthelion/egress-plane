package main

import "log/syslog"

func main() {
	w, err := syslog.New(syslog.LOG_INFO, "myapp")
	_ = err
	_ = w
}
