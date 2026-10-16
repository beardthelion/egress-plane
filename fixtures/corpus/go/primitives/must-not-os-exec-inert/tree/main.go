package main

import pkg "os/exec"

func main() {
    _ = pkg.Cmd.Example
    _ = pkg.ErrExample
    _ = pkg.Error.Error
    _ = pkg.Error.Unwrap
    _ = pkg.ExitError
    _ = pkg.ExitError.Error
    _ = pkg.LookPath
    _ = pkg.prefixSuffixSaver.Bytes
    _ = pkg.prefixSuffixSaver.Write
    _ = pkg.wrappedError.Error
    _ = pkg.wrappedError.Unwrap
}
