import std/options
import std/strformat
import std/strutils
import ./types
import ../util
import ../../lib/syslog
export types

type
  LengthError* = object of ValueError

# ==============================================================================
# Event Parsers
# ==============================================================================

# ------------------------------------------------------------------------------
# GATT Common Fields
# ------------------------------------------------------------------------------
proc parseGattEventCommon*(payload: string): GattEventCommon {.inline.} =
  result.gattResult = payload.getLeInt16(2)
  result.gattId = payload.getLe16(4)

# ------------------------------------------------------------------------------
# 1.4.4 GATT 接続通知
# ------------------------------------------------------------------------------
proc parseGattCommonConnectEvent*(payload: string): Option[GattConEvent] =
  const procName = "parseGattCommonConnectEvent"
  if not checkPayloadLen(procName, payload, 16):
    return
  try:
    var res: GattConEvent
    res.common = payload.parseGattEventCommon()
    res.attMtu = payload.getLe16(6)
    res.peer.addrType = payload.getU8(8).AddrType
    res.peer.address = payload.getBdAddr(9)
    res.peer.stringValue = res.peer.address.bdAddr2string()
    try:
      {.warning[HoleEnumConv]:off.}
      res.controlRole = payload.getU8(15).Role
    except:
      res.controlRole = Role.Error
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)
    let dumpStr = payload.hexDump()
    for line in dumpStr.splitLines:
      syslog.error(line)

# ------------------------------------------------------------------------------
# 1.4.7 GATT 切断通知
# ------------------------------------------------------------------------------
proc parseGattCommonDisconnectEvent*(payload: string): Option[GattDisconEvent] =
  const procName = "parseGattCommonDisconnectEvent"
  if not checkPayloadLen(procName, payload, 6):
    return
  try:
    var res: GattDisconEvent
    res.common = payload.parseGattEventCommon()
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.5.3: GATT Exchange MTU 通知
# ------------------------------------------------------------------------------
proc parseGattExchangeMtu*(payload: string): Option[GattExchangeMtuEvent] =
  const procName = "parseGattExchangeMtu"
  if not checkPayloadLen(procName, payload, 8):
    return
  try:
    var res: GattExchangeMtuEvent
    res.common = payload.parseGattEventCommon()
    res.serverMtu = payload.getLe16(6)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.5.6: GATT All Primary Services 通知
# ------------------------------------------------------------------------------
proc parseGattAllPrimaryServices*(payload: string): Option[GattAllPrimaryServices] =
  const procName = "parseGattAllPrimaryServices"
  if not checkPayloadLen(procName, payload, 168):
    return
  let common = payload.parseGattEventCommon()
  if common.gattResult != 0:
    return
  var res: GattAllPrimaryServices
  res.common = common
  let items = payload.getU8(6).int
  let uuidType = payload.getU8(7).ServiceUuidType
  for i in 0 ..< items:
    let startHandle = payload.getU8(8 + i * 2)
    let endHandle = payload.getU8(24 + i * 2)
    case uuidType
    of Uuid16:
      let uuid = Uuid(uuidType: uuidType, uuid16: payload.getUuid16(40 + i * 16))
      let svc = PrimaryServices(startHandle: startHandle, endHandle: endHandle,
          uuid: uuid)
      res.services.add(svc)
    of Uuid128:
      let uuid = Uuid(uuidType: uuidType, uuid128: payload.getUuid128(40 + i * 16))
      let svc = PrimaryServices(startHandle: startHandle, endHandle: endHandle,
          uuid: uuid)
      res.services.add(svc)
    else:
      discard
  result = some(res)

# ------------------------------------------------------------------------------
# 1.5.18: GATT All Charatreristic of a Service 通知
# ------------------------------------------------------------------------------
proc parseGattCharacteristicOfService*(payload: string):
    Option[GattCharacteristicsOfService] =
  const procName = "parseGattCharacteristicOfService"
  if not checkPayloadLen(procName, payload, 995):
    return
  var res: GattCharacteristicsOfService
  try:
    let uuidRawVal = payload.getU8(7)
    if not (uuidRawVal in [Uuid16.uint8, Uuid128.uint8]):
      raise newException(ValueError, &"Invalid UUID, {uuidRawVal}")
    let uuidType = uuidRawVal.ServiceUuidType
    res.common = payload.parseGattEventCommon()
    let nums = payload.getU8(6).int
    res.characteristics = newSeq[CharacteristicsOfService](nums)
    for i in 0 ..< nums:
      var ch: CharacteristicsOfService
      ch.chHandle = payload.getLe16(8 + i * 2)
      ch.properties = payload.getU8(100 + i)
      ch.attrHandle = payload.getLe16(146 + i * 2)
      case uuidType
      of Uuid16:
        let uuid = Uuid(uuidType: uuidType, uuid16: payload.getUuid16(238 + i * 16))
        ch.uuid = uuid
      of Uuid128:
        let uuid = Uuid(uuidType: uuidType, uuid128: payload.getUuid128(238 + i * 16))
        ch.uuid = uuid
      else:
        discard
      res.characteristics[i] = ch
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.5.26: GATT All Charatreristic Descriptors 通知
# ------------------------------------------------------------------------------
proc parseGattAllCharacteristicDescriptors*(payload: string):
    Option[GattAllCharacteristicDescriptors] =
  const procName = "parseGattAllCharacteristicDescriptors"
  if not checkPayloadLen(procName, payload, 1016):
    return
  var res: GattAllCharacteristicDescriptors
  try:
    let uuidRawVal = payload.getU8(7)
    if not (uuidRawVal in [Uuid16.uint8, Uuid128.uint8]):
      raise newException(ValueError, &"Invalid UUID, {uuidRawVal}")
    let uuidType = uuidRawVal.ServiceUuidType
    res.common = payload.parseGattEventCommon()
    let nums = payload.getU8(6).int
    res.characteristics = newSeq[CharacteristicDescriptor](nums)
    for i in 0 ..< nums:
      res.characteristics[i].handle = payload.getU8(8 + i * 2)
      case uuidType
      of Uuid16:
        let uuid = Uuid(uuidType: uuidType, uuid16: payload.getUuid16(120 + i * 16))
        res.characteristics[i].uuid = uuid
      of Uuid128:
        let uuid = Uuid(uuidType: uuidType, uuid128: payload.getUuid128(120 + i * 16))
        res.characteristics[i].uuid = uuid
      else:
        discard
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.5.30: GATT Read Characteristic Vluaes 通知
# ------------------------------------------------------------------------------
proc parseGattReadCharacteristicValue*(payload: string):
    Option[GattReadCharacteristicValueEvent] =
  const procName = "parseGattReadCharacteristicValue"
  if not checkPayloadLen(procName, payload, 520):
    return
  var res: GattReadCharacteristicValueEvent
  try:
    res.common = payload.parseGattEventCommon()
    let valueLen = payload.getLe16(6).int
    res.value = newSeq[uint8](valueLen)
    copyMem(addr res.value[0], addr payload[8], valueLen)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.5.33: GATT Read Using Characteristic UUID 通知
# ------------------------------------------------------------------------------
proc parseGattReadUsingCharacteristicUuid*(payload: string):
    Option[GattReadUsingCharacteristicUuidEvent] =
  const procName = "parseGattReadUsingCharacteristicUuid"
  if not checkPayloadLen(procName, payload, 1030):
    syslog.error(&"! {procName}: response payloadlen != 1030, {payload.len}.")
    return
  var res: GattReadUsingCharacteristicUuidEvent
  try:
    res.common = payload.parseGattEventCommon()
    let nums = payload.getU8(6).int
    let eachLen = payload.getU8(7).int
    if nums > 0:
      res.values = newSeq[HandleValue](nums)
      var pos = 8
      for i in 0 ..< nums:
        res.values[i].handle = payload.getLe16(pos)
        res.values[i].value = newSeq[uint8](eachLen - 2)
        copyMem(addr res.values[i].value[0], addr payload[pos + 2], eachLen - 2)
        pos.inc(eachLen)
      result = some(res)
    else:
      syslog.error(&"! {procName}: nums == 0, payload.len = {payload.len}.")
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.5.42: GATT Read Characteristic Descriptors 通知
# ------------------------------------------------------------------------------
proc parseGattReadCharacteristicDescriptors*(payload: string):
    Option[GattReadCharacteristicDescriptorsEvent] =
  const procName = "parseGattReadCharacteristicDescriptors"
  if not checkPayloadLen(procName, payload, 520):
    return
  var res: GattReadCharacteristicDescriptorsEvent
  try:
    res.common = payload.parseGattEventCommon()
    let descLen = payload.getLe16(6).int
    res.descs = newSeq[uint8](descLen)
    copyMem(addr res.descs[0], addr payload[8], descLen)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.5.70: GATT Handle Values 通知
# ------------------------------------------------------------------------------
proc parseGattHandleValuesEvent*(payload: string): Option[GattHandleValue] =
  const procName = "parseGattHandleValuesEvent"
  if payload.len != 529:
    let errmsg = &"! {procName}: payload length too short, {payload.len} [bytes]"
    syslog.error(errmsg)
    return
  try:
    var res: GattHandleValue
    res.common = payload.parseGattEventCommon()
    res.peer.addrType = payload.getU8(6).AddrType
    res.peer.address = payload.getBdAddr(7)
    res.peer.stringValue = res.peer.address.bdAddr2string()
    res.handle = payload.getLe16(13)
    let valueLen = payload.getLeInt16(15)
    if valueLen > 0:
      if payload.len < valueLen + 17:
        raise newException(LengthError, "Value size too big")
      res.values = newString(valueLen)
      copyMem(addr res.values[0], addr payload[17], valueLen)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)
