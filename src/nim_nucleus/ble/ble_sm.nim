import std/asyncdispatch
import std/strformat
import ./ble_client
import ./core/opc
import ./sm/types
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
