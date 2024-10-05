# Package

version       = "0.1.0"
author        = "Takeyoshi Kikuchi"
description   = "Nim binding for NetNucleus BLE stack"
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
installExt    = @["nim"]
bin           = @["btmd"]


# Dependencies

requires "nim >= 2.0.8"
requires "results >= 0.5.0"
