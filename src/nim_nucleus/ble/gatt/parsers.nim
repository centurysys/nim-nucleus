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
# 1.4.4 GATT 接続通知
# ------------------------------------------------------------------------------
proc parseGattCommonConnectEvent*(payload: string): Option[GattConEvent] =
  const procName = "parseGattCommonConnectEvent"
  if not checkPayloadLen(procName, payload, 16):
    return
  try:
    var res: GattConEvent
    res.gattResult = payload.getLe16(2)
    res.gattId = payload.getLe16(4)
    res.attMtu = payload.getLe16(6)
    res.peerAddrType = payload.getU8(8).AddrType
    res.peerAddr = payload.getBdAddr(9)
    res.controlRole = payload.getU8(15).Role
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
    res.gattResult = payload.getLe16(2)
    res.gattId = payload.getLe16(4)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)
