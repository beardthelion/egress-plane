package main

import "os/user"

func main() {
	var u user.User
	var g user.Group
	var e *user.UnknownUserError
	var gi *user.UnknownGroupIdError
	_, _, _, _ = u, g, e, gi
	_ = user.UnknownGroupError.Error
	_ = user.UnknownGroupIdError.Error
	_ = user.UnknownUserError.Error
	_ = user.UnknownUserIdError.Error
}
