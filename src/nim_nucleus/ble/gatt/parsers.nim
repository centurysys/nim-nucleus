import std/options
import std/strformat
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
proc parseGattEventCommon(payload: string): GattEventCommon {.inline.} =
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
    res.controlRole = payload.getU8(15).Role
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

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
# 1.5.70: GATT Handle Values 通知
# ------------------------------------------------------------------------------
proc parseGattHandleValuesEvent*(payload: string): Option[GattHandleValueEvent] =
  const procName = "parseGattHandleValuesEvent"
  if payload.len < 18:
    let errmsg = &"! {procName}: payload length too short, {payload.len} [bytes]"
    syslog.error(errmsg)
    return
  try:
    var res: GattHandleValueEvent
    res.common = payload.parseGattEventCommon()
    res.peer.addrType = payload.getU8(6).AddrType
    res.peer.address = payload.getBdAddr(7)
    res.handle = payload.getLe16(13)
    let valueLen = payload.getLeInt16(15)
    if valueLen > 0:
      if payload.len != valueLen + 17:
        raise newException(LengthError, "Payload size mismatch")
      res.values = newString(valueLen)
      copyMem(addr res.values[0], addr payload[17], valueLen)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)
