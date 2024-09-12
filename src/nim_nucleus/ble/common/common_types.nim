import std/options
import std/strformat
import std/strutils

type
  AddrType* {.pure.} = enum
    Public = 0x00'u8
    Random = 0x01'u8
  PeerAddr* = object
    addrType*: AddrType
    address*: uint64
  LocalAddr* = object
    addrType*: AddrType
    address*: uint64
  ServiceUuidType* = enum
    UuidError = (0x00, "???")
    Uuid16 = (0x01'u8, "UUID16")
    Uuid128 = (0x02'u8, "UUID128")
  Uuid* = object
    case uuidType*: ServiceUuidType
    of Uuid16:
      uuid16*: array[2, uint8]
    of Uuid128:
      uuid128*: array[16, uint8]
    else:
      discard

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
func toUuid128*(x: Uuid): Uuid =
  if x.uuidType == Uuid16:
    var uuid128: array[16, uint8] = [
      0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
      0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]
    uuid128[12] = x.uuid16[0]
    uuid128[13] = x.uuid16[1]
    result = Uuid(uuidType: Uuid128, uuid128: uuid128)
  else:
    result = x

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func `$`*(x: Uuid): string =
  case x.uuidType
  of Uuid128:
    var buf = newSeqOfCap[string](5)
    let u = x.uuid128
    buf.add(&"{u[15]:02x}{u[14]:02x}{u[13]:02x}{u[12]:02x}")
    buf.add(&"{u[11]:02x}{u[10]:02x}")
    buf.add(&"{u[9]:02x}{u[8]:02x}")
    buf.add(&"{u[7]:02x}{u[6]:02x}")
    buf.add(&"{u[5]:02x}{u[4]:02x}{u[3]:02x}{u[2]:02x}{u[1]:02x}{u[0]:02x}")
    result = buf.join("-")
  of Uuid16:
    let u = x.uuid16
    result = &"0000{u[1]:02x}{u[0]:02x}"
  else:
    discard

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
func str2uuid*(s: string): Option[Uuid] =
  const
    Uuid128sample = "00002a19-0000-1000-8000-00805f9b34fb"
    Uuid128parts = Uuid128sample.split("-")
  if s.len == 4:
    let val = s.parseHexInt().uint16
    let uuid16 = [val.lb, val.hb]
    let uuid = Uuid(uuidType: Uuid16, uuid16: uuid16)
    result = some(uuid)
  elif s.len == Uuid128sample.len:
    let parts = s.split("-")
    for i in 0 ..< Uuid128parts.len:
      if parts[i].len != Uuid128parts[i].len:
        return
    let concatUuid = parts.join("")
    var uuid128: array[16, uint8]
    for i in 0 ..< 16:
      let idx = 32 - ((i + 1) * 2)
      let val = concatUuid[idx..(idx + 1)].parseHexInt().uint8
      uuid128[i] = val
    result = some(Uuid(uuidType: Uuid128, uuid128: uuid128))

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
proc `$`*(x: PeerAddr): string =
  let addrType = if x.addrType == AddrType.Random: "Random" else: "Public"
  let address = x.address.bdAddr2string()
  result = &"{address} ({addrType})"
