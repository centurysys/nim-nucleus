import std/options
import std/strformat
import ./types
import ../util
import ../../lib/syslog
export types

# ==============================================================================
# Event Parsers
# ==============================================================================

# ------------------------------------------------------------------------------
# GATT Common Fields
# ------------------------------------------------------------------------------
proc parseGattEventCommon(payload: string): GattEventCommon {.inline.} =
  result.gattResult = payload.getLe16(2)
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
    res.peerAddrType = payload.getU8(8).AddrType
    res.peerAddr = payload.getBdAddr(9)
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
