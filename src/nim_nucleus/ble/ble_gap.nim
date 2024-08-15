import std/asyncdispatch
import std/options
import std/strformat
import ./ble_client
import ./core/hci_status
import ./core/opc
import ./gap/types
import ./util
import ../lib/syslog
export types

# ==============================================================================
# Requests
# ==============================================================================

# ------------------------------------------------------------------------------
# 1.2.11 LE Set Scan Parameters 要求
# ------------------------------------------------------------------------------
proc setScanParametersReq*(self: BleClient, scanType: ScanType, scanInterval: uint16 = 0x0010,
    scanWindow: uint16 = 0x0010, ownAddrType: AddrType, ownRandomAddrType: RandomAddrType,
    filterPolicy: ScanFilterPolicy = ScanFilterPolicy.AcceptAllExceptDirected):
    Future[bool] {.async.} =
  const
    procName = "setScanParametersReq"
    reqOpc = BTM_D_OPC_BLE_GAP_SET_SCAN_PARAMETERS_REQ
    expOpc = BTM_D_OPC_BLE_GAP_SET_SCAN_PARAMETERS_RSP
  var buf: array[10, uint8]
  buf.setOpc(0, reqOpc)
  buf[2] = scanType.uint8
  buf.setLe16(3, scanInterval)
  buf.setLe16(5, scanWindow)
  buf[7] = ownAddrType.uint8
  buf[8] = ownRandomAddrType.uint8
  buf[9] = filterPolicy.uint8
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ------------------------------------------------------------------------------
# 1.2.13 LE Set Scan Enable 要求
# ------------------------------------------------------------------------------
proc setScanEnableReq*(self: BleClient, scanEnable: bool, filterDuplicates: bool = true):
    Future[bool] {.async.} =
  const
    procName = "setScanParametersReq"
    reqOpc = BTM_D_OPC_BLE_GAP_SET_SCAN_ENABLE_REQ
    expOpc = BTM_D_OPC_BLE_GAP_SET_SCAN_ENABLE_RSP
  var buf: array[4, uint8]
  buf.setOpc(0, reqOpc)
  buf[2] = (if scanEnable: Scan.Enable else: Scan.Disable).uint8
  buf[3] = (if filterDuplicates: DuplicateFilter.Enable
      else: DuplicateFilter.Disable).uint8
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ==============================================================================
# Event Parsers
# ==============================================================================

# ------------------------------------------------------------------------------
# 1.2.15 LE Advertising Report 通知
# ------------------------------------------------------------------------------
proc parseAdvertisingReport*(self: BleClient, payload: string): Option[AdvertisingReport] =
  const procName = "parseAdertisingReport"
  if not checkPayloadLen(procName, payload, 43):
    return
  try:
    var res: AdvertisingReport
    res.eventType = payload[2].EventType
    res.addrType = payload[3].AddrType
    res.bdAddr = payload.getBdAddr(4)
    let dataLen = payload[10].uint8
    res.data = newString(dataLen)
    copyMem(addr res.data[0], addr payload[11], dataLen)
    res.rssi = payload[42].int8
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.71 LE Enhanced Connection Complete 通知
# ------------------------------------------------------------------------------
proc parseEnhConnectionComplete*(self: BleClient, payload: string):
    Option[EnhConnectionCompleteEvent] =
  const procName = "parseEnhConnectionComplete"
  if not checkPayloadLen(procName, payload, 32):
    return
  try:
    var res: EnhConnectionCompleteEvent
    res.hciStatus = payload[2].HciStatus
    res.conHandle = payload.getLe16(3)
    res.role = payload[5].Role
    res.peerAddrType = payload[6].AddrType
    res.peerAddr = payload.getBdAddr(7)
    res.localPrivateAddr = payload.getBdAddr(13)
    res.remotePrivateAddr = payload.getBdAddr(19)
    res.conInterval = payload.getLe16(25)
    res.conLatency = payload.getLe16(27)
    res.supervisionTimeout = payload.getLe16(29)
    res.masterClockAccuracy = payload[31].ClockAccuracy
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.2.78 LE Channel Selection Algorithm 通知
# ------------------------------------------------------------------------------
proc parseChannelSelAlgorithm*(self: BleClient, payload: string):
    Option[ChannelSelAlgorithmReport] =
  const procName = "parseChannelSelAlgorithm"
  if not checkPayloadLen(procName, payload, 5):
    return
  try:
    var res: ChannelSelAlgorithmReport
    res.conHandle = payload.getLe16(2)
    res.alg = payload[4].ChannSelAlgorithm
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)
