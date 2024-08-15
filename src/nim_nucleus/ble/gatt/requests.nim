import std/tables
import ./types

type
  # GATT 接続指示
  GattConnParams* = object
    filterPolicy*: bool
    ownAddrType*: AddrType
    randomAddrType*: RandomAddrType
    peerAddrType*: AddrType
    peerAddr*: uint64
    phys*: Table[PhyKind, ConnParams]
