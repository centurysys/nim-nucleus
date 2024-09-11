# Package

version       = "0.1.0"
author        = "Takeyoshi Kikuchi"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
installExt    = @["nim"]
bin           = @["nim_nucleus"]


# Dependencies

requires "nim >= 2.0.8"
requires "results >= 0.5.0"
