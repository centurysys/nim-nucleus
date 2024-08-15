import ../common/common_types
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
  LocalSecurity* = object
    peerAddrType*: PeerAddrType
    peerAddr*: uint64
    auth*: Authentication
    encKeySize*: uint8
    authorized*: bool
