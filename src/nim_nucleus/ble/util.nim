import std/options
import std/sequtils
import std/strformat
import std/strutils
import ./common/common_types
import ../lib/syslog

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc hexDump*(x: string, hexAddr = false): string =
  let linesize = if hexAddr: 16 else: 20
  var
    buf: seq[string]
    lines: seq[string]
    offsets = newSeqOfCap[string](linesize)
  for i in 0 ..< linesize:
    let offsetStr = if hexAddr: &"{i:02x}" else: &"{i:2d}"
    offsets.add(offsetStr)
  let addrHdr = offsets.join(" ")
  let header = &"\n     | {addrHdr}"
  lines.add(header)
  lines.add("-".repeat(header.len))
  for i, c in x.pairs:
    let offset = i mod linesize
    if offset == 0:
      buf.setLen(0)
    buf.add(&"{c.uint8:02x}")
    if (offset == (linesize - 1)) or i == (x.len - 1):
      let address = i - offset
      let content = buf.join(" ")
      let baseAddr = if hexAddr: &"{address:04x}" else: &"{address:4d}"
      let line = &"{baseAddr} | {content}"
      lines.add(line)
  result = lines.join("\n")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func toString*(buf: openArray[uint8|char]): string =
  result = newString(buf.len)
  copyMem(addr result[0], addr buf[0], buf.len)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func hb*(x: uint16): uint8 {.inline.} =
  result = ((x shr 8) and 0xff).uint8

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func lb*(x: uint16): uint8 {.inline.} =
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
func getOpc*(buf: openArray[uint8|char]|string, pos: int = 0): uint16 {.inline.} =
  result = (buf[pos].uint16 shl 8) or buf[pos + 1].uint16

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func getLe64*(buf: openArray[uint8|char]|string, pos: int): uint64 {.inline.} =
  for idx in 0 ..< 8:
    result = result or (buf[pos + idx].uint64 shl (idx * 8))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setLe16*(buf: var openArray[uint8|char], pos: int, val: uint16) {.inline.} =
  buf[pos] = val.lb
  buf[pos + 1] = val.hb

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func getLe16*(buf: openArray[uint8|char]|string, pos: int): uint16 {.inline.} =
  result = (buf[pos + 1].uint16 shl 8) or buf[pos].uint16

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func getLeInt16*(buf: openArray[uint8|char]|string, pos: int): int16 {.inline.} =
  result = cast[int16](getLe16(buf, pos))

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func getU8*(buf: openArray[uint8|char]|string, pos: int): uint8 {.inline.} =
  result = cast[uint8](buf[pos])

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func getS8*(buf: openArray[uint8|char]|string, pos: int): int8 {.inline.} =
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
func getBdAddr*(buf: openArray[uint8|char]|string, pos: int): uint64 =
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
func getUuid16*(buf: openArray[uint8|char]|string, pos: int): array[2, uint8] =
  for i in 0 ..< 2:
    result[i] = buf.getU8(pos + i)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func getUuid128*(buf: openArray[uint8|char]|string, pos: int): array[16, uint8] =
  for i in 0 ..< 16:
    result[i] = buf.getU8(pos + i)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setUuid16(buf: var openArray[uint8|char], pos: int, uuid16: array[2, uint8])
    {.inline.} =
  if buf.len < pos + 16:
    raise newException(EOFError, "buffer overflow")
  buf[pos] = Uuid16.uint8
  for i in 0 ..< 16:
    buf[pos + 1 + i] = if i < 2: uuid16[i] else: 0x00'u8

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setUuid128(buf: var openArray[uint8|char], pos: int, uuid128: array[16, uint8])
    {.inline.} =
  if buf.len < pos + 16:
    raise newException(EOFError, "buffer overflow")
  buf[pos] = Uuid128.uint8
  for i in 0 ..< 16:
    buf[pos + 1 + i] = uuid128[i]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setUuid*(buf: var openArray[uint8|char], pos: int, uuid: Uuid) =
  if pos < 0:
    raise newException(IndexDefect, "position must be 0 or above.")
  case uuid.uuidType
  of Uuid16:
    buf.setUuid16(pos, uuid.uuid16)
  of Uuid128:
    buf.setUuid128(pos, uuid.uuid128)
  else:
    discard

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc bdAddr2string*(x: uint64): string =
  var octets: array[6, string]
  for idx in 0 ..< 6:
    let octet = ((x shr (idx * 8)) and 0xff).uint8
    octets[5 - idx] = &"{octet:02X}"
  result = octets.join(":")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc string2bdAddr*(x: string): Option[uint64] =
  var address: uint64
  try:
    let buf = x.split(":").mapIt(it.parseHexInt)
    if buf.len != 6:
      return
    for idx, octet in buf.pairs:
      address = address or (octet.uint64 shl ((5 - idx) * 8))
    result = some(address)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! string2bdAddr: caught exception, \"{err}\"."
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc checkPayloadLen*(procName: string, payload: string, length: int): bool =
  if payload.len != length:
    let errmsg = &"! {procName}: payload length error, {payload.len} [bytes]"
    syslog.error(errmsg)
  else:
    result = true


when isMainModule:
  let bdaddrStr = "01:23:45:67:89:AB"
  let bdaddr = bdaddrStr.string2bdAddr()
  if bdaddr.isSome:
    echo &"{bdaddr.get():012X}"
  let s = "\x40\xb8\xfb\xff\x00\x00\x00\x00"
  let e = s.getLeInt16(2)
  echo e
