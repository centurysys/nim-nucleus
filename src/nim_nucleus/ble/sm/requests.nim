import ./types
export types

type
  RemoteDevice* = object
    addrType*: AddrType
    bdAddr*: uint64
