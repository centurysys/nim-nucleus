import std/tables
import ./types
export types

type
  # GATT 接続指示
  GattConnParams* = object
    filterPolicy*: bool
    ownAddrType*: AddrType
    randomAddrType*: RandomAddrType
    peer*: PeerAddr
    phys*: Table[PhyKind, ConnParams]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattDefaultGattConnParams*(peerAddr: uint64, random = true): GattConnParams =
  result.filterPolicy = false
  result.ownAddrType = AddrType.Public
  result.randomAddrType = RandomAddrType.NonResolvPrivate
  result.phys[Phy1M] = gattDefaultConnParams()
  result.peer.addrType = if random: AddrType.Random else: AddrType.Public
  result.peer.address = peerAddr
  result.peer.stringValue = peerAddr.bdAddr2string()
