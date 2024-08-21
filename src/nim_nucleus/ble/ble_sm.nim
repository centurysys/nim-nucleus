import std/asyncdispatch
import ./ble_client
import ./core/opc
import ./sm/types
import ./sm/requests
import ./sm/parsers
import ./util
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
# 1.3.5 LE ローカルデバイス Key 設定要求 (未使用)
# ------------------------------------------------------------------------------
proc setLocalDeviceKeyReq*(self: BleClient, irk: array[16, uint8],
    dhk: array[32, uint8]): Future[bool] {.async.} =
  const
    procName = "setLocalDeviceKeyReq"
    reqOpc = BTM_D_OPC_BLE_SM_LOCAL_DEVICE_KEY_SET_REQ
    expOpc = BTM_D_OPC_BLE_SM_LOCAL_DEVICE_KEY_SET_RSP
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


when isMainmodule:
  import std/strformat
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
