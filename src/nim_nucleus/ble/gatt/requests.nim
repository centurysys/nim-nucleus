import std/tables
import ./types

type
  # GATT 接続指示
  GattConnParams* = object
    filterPolicy*: bool
    ownAddrType*: DirectAddrType
    randomAddrType*: RandomAddrType
    peerAddrType*: DirectAddrType
    peerAddr*: uint64
    phys*: Table[PhyKind, ConnParams]
