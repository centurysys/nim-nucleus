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
