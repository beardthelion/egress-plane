package main

import pkg "go/build"

func main() {
    _ = pkg.AllowBinary
    _ = pkg.ArchChar
    _ = pkg.Context
    _ = pkg.Context.MatchFile
    _ = pkg.Context.SrcDirs
    _ = pkg.Default
    _ = pkg.Directive
    _ = pkg.FindOnly
    _ = pkg.IgnoreVendor
    _ = pkg.ImportComment
    _ = pkg.ImportMode
    _ = pkg.IsLocalImport
    _ = pkg.MultiplePackageError
    _ = pkg.MultiplePackageError.Error
    _ = pkg.NoGoError
    _ = pkg.NoGoError.Error
    _ = pkg.Package
    _ = pkg.Package.IsCommand
    _ = pkg.ToolDir
}
