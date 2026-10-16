package main

import pkg "runtime/debug"

func main() {
    _ = pkg.BuildInfo
    _ = pkg.BuildInfo.String
    _ = pkg.BuildSetting
    _ = pkg.CrashOptions
    _ = pkg.FreeOSMemory
    _ = pkg.GCStats
    _ = pkg.Module
    _ = pkg.ParseBuildInfo
    _ = pkg.ReadBuildInfo
    _ = pkg.ReadGCStats
    _ = pkg.SetExample
}
