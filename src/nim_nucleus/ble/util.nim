import std/strformat
import std/strutils

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toString*(buf: openArray[uint8|char]): string =
  result = newString(buf.len)
  copyMem(addr result[0], addr buf[0], buf.len)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func hb(x: uint16): uint8 {.inline.} =
  result = ((x shr 8) and 0xff).uint8

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func lb(x: uint16): uint8 {.inline.} =
  result = (x and 0xff).uint8

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setOpc*(buf: var openArray[uint8|char], pos: int, opc: uint16) {.inline.} =
  buf[pos] = opc.hb
  buf[pos + 1] = opc.lb

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc getOpc*(buf: openArray[uint8|char]|string, pos: int = 0): uint16 {.inline.} =
  result = (buf[0].uint16 shl 8) or buf[1].uint16

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setLe16*(buf: var openArray[uint8|char], pos: int, val: uint16) {.inline.} =
  buf[pos] = val.lb
  buf[pos + 1] = val.hb

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc getLe16*(buf: openArray[uint8|char]|string, pos: int): uint16 {.inline.} =
  result = (buf[1].uint16 shl 8) or buf[0].uint16

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc getLeInt16*(buf: openArray[uint8|char]|string, pos: int): int16 {.inline.} =
  result = cast[int16](getLe16(buf, pos))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc getU8*(buf: openArray[uint8|char]|string, pos: int): uint8 {.inline.} =
  result = cast[uint8](buf[pos])

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc getS8*(buf: openArray[uint8|char]|string, pos: int): int8 {.inline.} =
  result = cast[int8](buf[pos])

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setBdAddr*(buf: var openArray[uint8|char], pos: int, bdAddr: uint64) =
  for idx in 0 ..< 6:
    let octet = ((bdAddr shr (idx * 8)) and 0xff).uint8
    buf[pos + idx] = octet

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc getBdAddr*(buf: openArray[uint8|char]|string, pos: int): uint64 =
  for idx in 0 ..< 6:
    result = result or (buf[pos + idx].uint64 shl (idx * 8))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setLeArray*(buf: var openArray[uint8|char], pos: int, val: openArray[uint8],
    len: int) =
  for idx in 0 ..< len:
    buf[pos + idx] = val[idx]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc getLeArray*(buf: openArray[uint8|char]|string, pos: int, len: int): seq[uint8] =
  result = newSeqOfCap[uint8](len)
  for idx in 0 ..< len:
    result.add(buf[pos + idx].uint8)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc getLeArray*(src: openArray[uint8|char]|string, dest: var openArray[uint8],
    pos: int, len: int) =
  for idx in 0 ..< len:
    dest[idx] = src[pos + idx].uint8

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc bdAddr2string*(x: uint64): string =
  var octets: array[6, string]
  for idx in 0 ..< 6:
    let octet = ((x shr (idx * 8)) and 0xff).uint8
    octets[5 - idx] = &"{octet:02X}"
  result = octets.join(":")
