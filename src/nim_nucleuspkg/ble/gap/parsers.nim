import std/options
import std/strformat
import ../core/hci_status
import ./types
import ../util
import ../../lib/syslog
export types

# ==============================================================================
# Event Parsers
# ==============================================================================

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseAdvertisingData(self: var AdvertisingReport, payload: string) =
  var pos = 0
  while pos < payload.len - 3:
    let len = payload.getU8(pos).int
    let kind = payload.getU8(pos + 1)
    case kind
    of AdType.Flags.uint8:
      let flags = payload.getU8(pos + 2)
      self.flags = some(flags)
    of AdType.ShortName.uint8, AdType.CompleteName.uint8:
      let name = payload.getLeArray(pos + 2, len - 1)
      if name.len > 0:
        self.name = some(name.toString)
    of AdType.ManufacturerSpecific.uint8:
      let data = payload.getLeArray(pos + 2, len - 1)
      if data.len > 0:
        self.manufacturerData = some(data.toString)
    else:
      discard
    pos.inc(len + 1)

# ------------------------------------------------------------------------------
# 1.2.15 LE Advertising Report 通知
# ------------------------------------------------------------------------------
proc parseAdvertisingReport*(payload: string): Option[AdvertisingReport] =
  const procName = "parseAdertisingReport"
  if not checkPayloadLen(procName, payload, 43):
    return
  try:
    var res: AdvertisingReport
    res.eventType = payload.getU8(2).EventType
    res.peer.addrType = payload.getU8(3).AddrType
    res.peer.address = payload.getBdAddr(4)
    res.peer.stringValue = res.peer.address.bdAddr2string()
    let dataLen = payload.getU8(10).int
    if dataLen > 0:
      res.rawdata = newString(dataLen)
      copyMem(addr res.rawdata[0], addr payload[11], dataLen)
      res.parseAdvertisingData(res.rawdata)
    res.rssi = payload.getS8(42)
    result = some(res)
  except:
    let e = getCurrentException()
    echo e.getStackTrace()
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.16 LE Connection Complete 通知
# ------------------------------------------------------------------------------
proc parseConnectionComplete*(payload: string): Option[ConnectionCompleteEvent] =
  const procName = "parseConnectionComplete"
  if not checkPayloadLen(procName, payload, 20):
    return
  try:
    var res: ConnectionCompleteEvent
    res.hciStatus = payload.getU8(2).toHciStatus
    res.conHandle = payload.getLe16(3)
    res.role = payload.getU8(5).Role
    res.peer.addrType = payload.getU8(6).AddrType
    res.peer.address = payload.getBdAddr(7)
    res.peer.stringValue = res.peer.address.bdAddr2string()
    res.conInterval = payload.getLe16(13)
    res.conLatency = payload.getLe16(15)
    res.supervisionTimeout = payload.getLe16(17)
    res.masterClockAccuracy = payload.getU8(19).ClockAccuracy
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.19 LE Disconnection Compete 通知
# ------------------------------------------------------------------------------
proc parseDisconnectionComplete*(payload: string): Option[DisconnectionCompleteEvent] =
  const procName = "parseDisconnectionComplete"
  if not checkPayloadLen(procName, payload, 6):
    return
  try:
    var res: DisconnectionCompleteEvent
    res.hciStatus = payload.getU8(2).toHciStatus
    res.conHandle = payload.getLe16(3)
    res.reason = payload.getU8(5).toHciStatus
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.30 LE Connection Update 通知
# ------------------------------------------------------------------------------
proc parseConnectionUpdate*(payload: string): Option[ConnectionUpdateEvent] =
  const procName = "parseConnectionUpdate"
  if not checkPayloadLen(procName, payload, 11):
    return
  try:
    var res: ConnectionUpdateEvent
    res.hciStatus = payload.getU8(2).toHciStatus
    res.conHandle = payload.getLe16(3)
    res.conInterval = payload.getLe16(5)
    res.conLatency = payload.getLe16(7)
    res.supervisionTimeout = payload.getLe16(9)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.35 LE Read Remote Used Features 通知
# ------------------------------------------------------------------------------
proc parseRemoteUsedFeatures*(payload: string): Option[RemoteUsedFeatures] =
  const procName = "parseRemoteUsedFeatures"
  if not checkPayloadLen(procName, payload, 13):
    return
  try:
    var res: RemoteUsedFeatures
    res.hciStatus = payload.getU8(2).toHciStatus
    res.conHandle = payload.getLe16(3)
    res.features = payload.getLe64(5)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.36 LE Encryption Change 通知
# ------------------------------------------------------------------------------
proc parseEncryptionChange*(payload: string): Option[EncryptionChangeEvent] =
  const procName = "parseEncryptionChange"
  if not checkPayloadLen(procName, payload, 6):
    return
  try:
    var res: EncryptionChangeEvent
    res.hciStatus = payload.getU8(2).toHciStatus
    res.conHandle = payload.getLe16(3)
    res.encryptionEnabled = payload.getU8(5) == 0x01'u8
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.71 LE Enhanced Connection Complete 通知
# ------------------------------------------------------------------------------
proc parseEnhConnectionComplete*(payload: string): Option[EnhConnectionCompleteEvent] =
  const procName = "parseEnhConnectionComplete"
  if not checkPayloadLen(procName, payload, 32):
    return
  try:
    var res: EnhConnectionCompleteEvent
    res.hciStatus = payload.getU8(2).toHciStatus
    res.conHandle = payload.getLe16(3)
    res.role = payload.getU8(5).Role
    res.peer.addrType = payload.getU8(6).AddrType
    res.peer.address = payload.getBdAddr(7)
    res.peer.stringValue = res.peer.address.bdAddr2string()
    res.localPrivateAddr = payload.getBdAddr(13)
    res.remotePrivateAddr = payload.getBdAddr(19)
    res.conInterval = payload.getLe16(25)
    res.conLatency = payload.getLe16(27)
    res.supervisionTimeout = payload.getLe16(29)
    res.masterClockAccuracy = payload.getU8(31).ClockAccuracy
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.78 LE Channel Selection Algorithm 通知
# ------------------------------------------------------------------------------
proc parseChannelSelAlgorithm*(payload: string): Option[ChannelSelAlgorithmReport] =
  const procName = "parseChannelSelAlgorithm"
  if not checkPayloadLen(procName, payload, 5):
    return
  try:
    var res: ChannelSelAlgorithmReport
    res.conHandle = payload.getLe16(2)
    res.alg = payload.getU8(4).ChannSelAlgorithm
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)
