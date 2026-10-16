package main

import pkg "os/user"

func main() {
    _ = pkg.Group
    _ = pkg.UnknownExample
    _ = pkg.UnknownGroupError.Error
    _ = pkg.UnknownGroupIdError.Error
    _ = pkg.UnknownUserError.Error
    _ = pkg.UnknownUserIdError.Error
    _ = pkg.User
}
