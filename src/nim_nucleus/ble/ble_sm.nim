import std/asyncdispatch
import std/options
import std/strformat
import ./ble_client
import ./core/opc
import ./core/sm_reason
import ./sm/types
import ./sm/requests
import ./util
import ../lib/syslog
export types

# ------------------------------------------------------------------------------
# 1.3.1 LE ローカル IO Capabilities 設定要求
# ------------------------------------------------------------------------------
proc setLocalIoCapabilitiesReq*(self: BleClient, ioCap: IoCap): Future[bool]
    {.async.} =
  const
    procName = "setLocalIoCapabilitiesReq"
    reqOpc = BTM_D_OPC_BLE_SM_LOCAL_IO_CAPABILITIES_SET_REQ
    expOpc = BTM_D_OPC_BLE_SM_LOCAL_IO_CAPABILITIES_SET_RSP
  var buf: array[3, uint8]
  buf.setOpc(0, reqOpc)
  buf[2] = ioCap.uint8
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ------------------------------------------------------------------------------
# 1.3.3 LE セキュリティモード設定要求
# ------------------------------------------------------------------------------
proc setSecurityModeReq*(self: BleClient, mode: SecurityMode): Future[bool]
    {.async.} =
  const
    procName = "setSecurityModeReq"
    reqOpc = BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_REQ
    expOpc = BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_RSP
  var buf: array[3, uint8]
  buf.setOpc(0, reqOpc)
  buf[2] = mode.uint8
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ------------------------------------------------------------------------------
# 1.3.5 LE ローカルデバイス Key 設定要求
# ------------------------------------------------------------------------------
proc setLocalDeviceKeyReq*(self: BleClient, irk: array[16, uint8],
    dhk: array[32, uint8]): Future[bool] {.async.} =
  const
    procName = "setLocalDeviceKeyReq"
    reqOpc = BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_REQ
    expOpc = BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_RSP
  var buf: array[50, uint8]
  buf.setOpc(0, reqOpc)
  buf.setLeArray(2, irk, 16)
  buf.setLeArray(18, dhk, 32)
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ------------------------------------------------------------------------------
# 1.3.7 LE リモート Collection Key 設定要求
# ------------------------------------------------------------------------------
proc setRemoteCollectionKeyReq*(self: BleClient, keys: RemoteCollectionKey):
    Future[bool] {.async.} =
  const
    procName = "setRemoteCollectionKeyReq"
    reqOpc = BTM_D_OPC_BLE_SM_REMOTE_COLLECTION_KEY_SET_REQ
    expOpc = BTM_D_OPC_BLE_SM_REMOTE_COLLECTION_KEY_SET_RSP
  var buf: array[70, uint8]
  buf.setOpc(0, reqOpc)
  buf[2] = keys.addrType.uint8
  buf.setBdAddr(3, keys.peerAddr)
  buf[9] = keys.auth.uint8
  buf[10] = keys.encKeySize
  buf.setLeArray(11, keys.irk, 16)
  buf.setLeArray(27, keys.ltk, 16)
  buf.setLeArray(43, keys.csrk, 16)
  buf.setLeArray(59, keys.rand, 8)
  buf.setLe16(67, keys.ediv)
  buf[69] = keys.authorized.uint8
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ------------------------------------------------------------------------------
# 1.3.11 LE リモートデバイス Key 削除要求
# ------------------------------------------------------------------------------
proc deleteRemoteDeviceKeyReq*(self: BleClient, device: RemoteDevice):
    Future[bool] {.async.} =
  const
    procName = "deleteRemoteDeviceKeyReq"
    reqOpc = BTM_D_OPC_BLE_SM_REMOTE_DEVICE_KEY_DELETE_REQ
    expOpc = BTM_D_OPC_BLE_SM_REMOTE_DEVICE_KEY_DELETE_RSP
  var buf: array[9, uint8]
  buf.setOpc(0, reqOpc)
  buf[2] = device.addrType.uint8
  buf.setBdAddr(3, device.bdAddr)
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ==============================================================================
# Event Parsers
# ==============================================================================

# ------------------------------------------------------------------------------
# 1.3.18 LE ローカルセキュリティ 設定通知
# ------------------------------------------------------------------------------
proc parseLocalSecurityPropertyEvent*(self: BleClient, payload: string):
    Option[LocalSecurity] =
  const procName = "parseLocalSecurityPropertyEvent"
  if not checkPayloadLen(procName, payload, 12):
    return
  try:
    var res: LocalSecurity
    res.peer.addrType = payload[2].AddrType
    res.peer.address = getBdAddr(payload, 3)
    res.auth = payload[9].Authentication
    res.encKeySize = payload[10].uint8
    res.authorized = if payload[11].Authorization == Authorization.Completed: true
        else: false
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.19 LE LTK 受信通知
# ------------------------------------------------------------------------------
proc parseLtkReceiveEvent*(self: BleClient, payload: string): Option[PeerLtk] =
  const procName = "parseLtkReceiveEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: PeerLtk
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.ltk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.20 LE EDIV Rand 受信通知
# ------------------------------------------------------------------------------
proc parseEdivRandReceiveEvent*(self: BleClient, payload: string): Option[PeerEdivRand] =
  const procName = "parseEdivRandReceiveEvent"
  if not checkPayloadLen(procName, payload, 19):
    return
  try:
    var res: PeerEdivRand
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    res.ediv = payload.getLe16(9)
    payload.getLeArray(res.rand, 11, 8)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.22 LE Address Information 受信通知
# ------------------------------------------------------------------------------
proc parseAddressInfoReceiveEvent*(self: BleClient, payload: string): Option[PeerAddressInfo] =
  const procName = "parseAddressInfoReceiveEvent"
  if not checkPayloadLen(procName, payload, 16):
    return
  try:
    var res: PeerAddressInfo
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    res.peerId.addrType = payload[9].AddrType
    res.peerId.address = payload.getBdAddr(10)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.23 LE CSRK 受信通知
# ------------------------------------------------------------------------------
proc parseCsrkReceiveEvent*(self: BleClient, payload: string): Option[PeerCsrk] =
  const procName = "parseCsrkReceiveEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: PeerCsrk
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.csrk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.24 LE LTK 送信通知
# ------------------------------------------------------------------------------
proc parseLtkSendEvent*(self: BleClient, payload: string): Option[PeerLtk] =
  const procName = "parseLtkSendEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: PeerLtk
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.ltk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.25 LE EDIV Rand 送信通知
# ------------------------------------------------------------------------------
proc parseEdivRandSendEvent*(self: BleClient, payload: string): Option[PeerEdivRand] =
  const procName = "parseEdivRandSendEvent"
  if not checkPayloadLen(procName, payload, 19):
    return
  try:
    var res: PeerEdivRand
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    res.ediv = payload.getLe16(9)
    payload.getLeArray(res.rand, 11, 8)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.26 LE IRK 送信通知
# ------------------------------------------------------------------------------
proc parseIrkSendEvent*(self: BleClient, payload: string): Option[LocalIrk] =
  const procName = "parseIrkSendEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: LocalIrk
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.irk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.27 LE Address Information 送信通知
# ------------------------------------------------------------------------------
proc parseAddressInfoSendEvent*(self: BleClient, payload: string): Option[LocalAddr] =
  const procName = "parseAddressInfoSendEvent"
  if not checkPayloadLen(procName, payload, 9):
    return
  try:
    var res: LocalAddr
    res.addrType = payload[2].AddrType
    res.address = payload.getBdAddr(3)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.28 LE CSRK 送信通知
# ------------------------------------------------------------------------------
proc parseCsrkSendEvent*(self: BleClient, payload: string): Option[PeerCsrk] =
  const procName = "parseCsrkSendEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: PeerCsrk
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.csrk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.29 LE 認証完了通知
# ------------------------------------------------------------------------------
proc parseAuthenticationCompleteEvent*(self: BleClient, payload: string): Option[PeerAddr] =
  const procName = "parseAuthenticationCompleteEvent"
  if not checkPayloadLen(procName, payload, 9):
    return
  try:
    var res: PeerAddr
    res.addrType = payload[2].AddrType
    res.address = payload.getBdAddr(3)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.34 LE 認証失敗通知
# ------------------------------------------------------------------------------
proc parseAuthenticationFailEvent*(self: BleClient, payload: string): Option[AuthFailInfo] =
  const procName = "parseAuthenticationFailEvent"
  if not checkPayloadLen(procName, payload, 10):
    return
  try:
    var res: AuthFailInfo
    res.peer.addrType = payload[2].AddrType
    res.peer.address = payload.getBdAddr(3)
    res.smReason = payload[9].SmReason
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)


when isMainmodule:
  import std/strutils

  var cmd: array[3, uint8]
  cmd.setOpc(0, BTM_D_OPC_BLE_SM_LOCAL_IO_CAPABILITIES_SET_REQ)
  cmd[2] = IoCap.NoInputNoOutput.uint8
  let payload = cmd.toString()
  echo payload.len
  var buf = newSeqOfcap[string](cmd.len)
  for s in payload:
    buf.add(&"0x{s.uint8:02x}")
  echo buf.join(" ")
