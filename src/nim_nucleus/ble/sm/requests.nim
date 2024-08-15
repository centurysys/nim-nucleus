import ./types
export types

type
  RemoteCollectionKey* = object
    addrType*: AddrType
    peerAddr*: uint64
    auth*: Authentication
    encKeySize*: uint8
    irk*: array[16, uint8]
    ltk*: array[16, uint8]
    csrk*: array[16, uint8]
    rand*: array[8, uint8]
    ediv*: uint16
    authorized*: bool
  RemoteDevice* = object
    addrType*: AddrType
    bdAddr*: uint64
