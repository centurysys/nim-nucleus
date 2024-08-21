import ../common/common_types
import ../gap/types
export common_types, types

type
  PhyKind* = enum
    Phy1M = 0x01'u8
    Phy2M = 0x02'u8
    PhyCoded = 0x04'u8
  ConnParams* = object
    scanInterval*: uint16
    scanWindow*: uint16
    conIntervalMin*: uint16
    conIntervalMax*: uint16
    conLatency*: uint16
    supervisionTimeout*: uint16
    minCeLength*: uint16
    maxCeLength*: uint16

# Event (Common)
type
  # 1.4.4 GATT 接続通知
  GattConEvent* = object
    gattResult*: uint16
    gattId*: uint16
    attMtu*: uint16
    peerAddrType*: AddrType
    peerAddr*: uint64
    controlRole*: Role
  # 1.4.7 GATT 切断通知
  GattDisconEvent* = object
    gattResult*: uint16
    gattId*: uint16

# Event (Client)
type
  # 1.5.70 GATT Handle Value 通知
  GattHandleValueEvent* = object
    gattResult*: uint16
    gattId*: uint16
    peerAddrType*: AddrType
    peerAddr*: uint64
    handle*: uint16
    values*: string
