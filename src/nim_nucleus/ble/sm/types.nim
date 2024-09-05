import std/strformat
import std/strutils
import ../common/common_types
import ../core/sm_reason
import ../gap/types
export common_types, types

type
  IoCap* {.pure.} = enum
    DisplayOnly = 0x00'u8
    DisplayYesNo = 0x01'u8
    KeyboardOnly = 0x02'u8
    NoInputNoOutput = 0x03'u8
    KeyboardDisplay = 0x04'u8
  SecurityMode* {.pure.} = enum
    NoAuth = 0x01'u8
    Level2 = 0x02'u8
    Level4 = 0x06'u8
  Irk* = object
    bytes*: array[16, uint8]
  Dhk* = object
    bytes*: array[32, uint8]
  Authentication* {.pure.} = enum
    NoSecurity = (0x00'u8, "No serucity")
    UnAuth = (0x01'u8, "Unauthenticated pairing")
    UnAuthSecure = (0x02'u8, "Unauthenticated Secure Connetions pairing")
    Auth = (0x03'u8, "Authenticated pairing")
    AuthSecure = (0x04'u8, "Authenticated Secure Connetions pairing")
  Authorization* {.pure.} = enum
    NotCompleted = (0x00'u8, "Authorization not completed")
    Completed = (0x01, "Authorization completed")

type
  RemoteCollectionKeys* = object
    peer*: PeerAddr
    bdAddrStr*: string
    auth*: Authentication
    encKeySize*: uint8
    irk*: array[16, uint8]
    ltk*: array[16, uint8]
    csrk*: array[16, uint8]
    rand*: array[8, uint8]
    ediv*: uint16
    authorized*: bool
    valid*: bool

# Event
type
  # 1.3.18 LE ローカルセキュリティ設定通知 (0x407C)
  LocalSecurity* = object
    peer*: PeerAddr
    auth*: Authentication
    encKeySize*: uint8
    authorization*: bool
  # 1.3.19 LE LTK 受信通知 (0x405D) / 1.3.24 LE LTK 送信通知 (0x4072)
  LtkEvent* = object
    peer*: PeerAddr
    ltk*: array[16, uint8]
  # 1.3.20 LE EDIV Rand 受信通知 (0x405E) / 1.3.25 LE EDIV Rand 送信通知 (0x4073)
  EdivRandEvent* = object
    peer*: PeerAddr
    ediv*: uint16
    rand*: array[8, uint8]
  # 1.3.21 LE IRK 受信通知 (0x405F) / 1.3.26 LE IRK 送信通知 (0x4074)
  IrkEvent* = object
    peer*: PeerAddr
    irk*: array[16, uint8]
  # 1.3.22 LE Address Information 受信通知 (0x4070)
  # 1.3.27 LE Address Information 送信通知 (0x4075)
  AddressInfoEvent* = object
    peer*: PeerAddr
    peerId*: PeerAddr
  # 1.3.23 LE CSRK 受信通知 (0x4071) / 1.3.28 LE CSRK 送信通知 (0x4076)
  CsrkEvent* = object
    peer*: PeerAddr
    csrk*: array[16, uint8]
  # 1.3.29 LE 認証完了通知
  AuthCompleteEvent* = object
    peer*: PeerAddr
  # 1.3.34 LE 認証失敗通知 (0x407B)
  AuthFailInfo* = object
    peer*: PeerAddr
    smReason*: SmReason

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc toString(x: openArray[uint8]): string =
  let size = x.len
  var buf = newSeqOfCap[string](size)
  for i in 0 ..< size:
    let val = x[i]
    buf.add(&"{val:02x}")
  result = buf.join(":")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(key: RemoteCollectionKeys): string =
  var buf = newSeqOfCap[string](10)
  buf.add("--- RemoteCollectionKeys ---")
  buf.add(&"* Address: {key.peer.address.bdAddr2string} ({key.peer.addrType})")
  buf.add(&"* Authentication: {key.auth}")
  buf.add(&"* EncKeySize: {key.encKeysize}")
  buf.add(&"* IRK:  {key.irk.toString}")
  buf.add(&"* LTK:  {key.ltk.toString}")
  buf.add(&"* CSRK: {key.csrk.toString}")
  buf.add(&"* Rand: {key.rand.toString}")
  buf.add(&"* Ediv: 0x{key.ediv:04x}")
  buf.add(&"* Authorized: {key.authorized}")
  buf.add(&"* Valid: {key.valid}")
  result = buf.join("\n")
