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
  CharProperties* = enum
    pRead = (0x02'u8, "Read")
    pWriteWoResp = (0x04'u8, "Write Without Response")
    pWrite = (0x08'u8, "Write")
    pNotify = (0x10'u8, "Notify")
    pIndicate = (0x20'u8, "Indicate")
  PrimaryServices* = object
    startHandle*: uint16
    endHandle*: uint16
    uuid*: Uuid
  CharacteristicsOfService* = object
    chHandle*: uint16
    properties*: uint8
    attrHandle*: uint16
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
  # 1.5.18 GATT All Characteristics of a Service 通知
  GattAllCharacteristicsOfService* = object
    common*: GattEventCommon
    characteristics*: seq[CharacteristicsOfService]
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
proc toUuid128*(x: Uuid): Uuid =
  if x.uuidType == Uuid16:
    var uuid128: array[16, uint8] = [
      0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
      0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]
    uuid128[12] = x.uuid16[0]
    uuid128[13] = x.uuid16[1]
    result = Uuid(uuidType: Uuid128, uuid128: uuid128)
  else:
    result = x

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

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(x: PrimaryServices): string =
  result = &"attr handle: 0x{x.startHandle:04x}," &
      &" end grp handle: 0x{x.endHandle:04x}" &
      &" uuid: {x.uuid.toUuid128}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(x: CharacteristicsOfService): string =
  var buf = newSeqOfCap[string](4)
  buf.add(&"handle: 0x{x.chHandle:04x}")
  buf.add(&"char properties: 0x{x.properties:02x}")
  buf.add(&"char value handle: 0x{x.attrHandle:04x}")
  buf.add(&"uuid: {x.uuid.toUuid128}")
  result = buf.join(", ")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(x: CharacteristicDescriptor): string =
  result = &"handle: 0x{x.handle:04x}, uuid: {x.uuid.toUuid128}"


when isMainModule:
  let uuid = Uuid(uuidType: Uuid16, uuid16: [0x00, 0x2a])
  echo uuid.toUuid128
