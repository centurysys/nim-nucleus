# Package

version       = "0.10.2"
author        = "Takeyoshi Kikuchi"
description   = "Nim binding for NetNucleus BLE stack"
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
installExt    = @["nim"]
bin           = @["app/btmd"]
skipDirs      = @["app"]


# Dependencies

requires "nim >= 2.2.4"
requires "results >= 0.5.1"
requires "argparse == 0.10.1"
requires "pretty >= 0.2.0"
