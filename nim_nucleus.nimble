# Package

version       = "0.1.0"
author        = "Takeyoshi Kikuchi"
description   = "Nim binding for NetNucleus BLE stack"
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
installExt    = @["nim"]
bin           = @["app/btmd"]
skipDirs      = @["app"]


# Dependencies

requires "nim >= 2.2.0"
requires "results >= 0.5.0"
requires "argparse == 0.10.1"
requires "pretty >= 0.1.0"
