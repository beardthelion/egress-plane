package main

import "log/syslog"

func main() {
	var p syslog.Priority
	var w *syslog.Writer
	_, _ = p, w
	_ = syslog.LOG_INFO
	_ = syslog.Writer.Write
}
