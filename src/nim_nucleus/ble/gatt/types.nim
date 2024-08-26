import std/strformat
import std/strutils
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
  PrimaryServices* = object
    startHandle*: uint16
    endHandle*: uint16
    uuid*: Uuid
  CharacteristicDescriptor* = object
    handle*: uint16
    uuid*: Uuid

# Event (Common)
type
  GattEventCommon* = object
    gattResult*: int16
    gattId*: uint16
  # 1.4.4 GATT 接続通知
  GattConEvent* = object
    common*: GattEventCommon
    attMtu*: uint16
    peer*: PeerAddr
    controlRole*: Role
  # 1.4.7 GATT 切断通知
  GattDisconEvent* = object
    common*: GattEventCommon

# Event (Client)
type
  # 1.5.3 GATT Exchange MTU 通知
  GattExchangeMtuEvent* = object
    common*: GattEventCommon
    serverMtu*: uint16
  # 1.5.6 GATT All Primary Services 通知
  GattAllPrimaryServices* = object
    common*: GattEventCommon
    services*: seq[PrimaryServices]
  # 1.5.26 GATT All Charatrerictic Descriptors 通知
  GattAllCharacteristicDescriptors* = object
    common*: GattEventCommon
    characteristics*: seq[CharacteristicDescriptor]
  # 1.5.30 GATT Read Characteristic Value 通知
  GattReadCharacteristicValueEvent* = object
    common*: GattEventCommon
    value*: seq[uint8]

  # 1.5.70 GATT Handle Value 通知
  GattHandleValueEvent* = object
    common*: GattEventCommon
    peer*: PeerAddr
    handle*: uint16
    values*: string

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattDefaultConnParams*(): ConnParams =
  result.scanInterval = 0x0020
  result.scanWindow = 0x0012
  result.conIntervalMin = 0x0032
  result.conIntervalMax = 0x0046
  result.conLatency = 0
  result.supervisionTimeout = 0x07d0
  result.minCeLength = 0
  result.maxCeLength = 0

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(x: Uuid): string =
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
