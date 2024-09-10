import std/asyncdispatch
import std/options
import std/strformat
import std/tables
import ./ble_client
import ./notifications
import ./core/opc
import ./core/gatt_result
import ./core/hci_status
import ./gatt/requests
import ./gatt/types
import ./util
import ../lib/syslog
export types, requests

# ------------------------------------------------------------------------------
# Send Instruction/Receive Confirmation
# ------------------------------------------------------------------------------
proc btmInstruction(self: BleClient, procName: string, payload: string,
    expectedOpc: uint16): Future[Option[int16]] {.async.} =
  let res_opt = await self.btmSendRecv(payload)
  if res_opt.isNone:
    let errmsg = &"! {procName}: failed"
    syslog.error(errmsg)
    return
  let response = res_opt.get()
  let resOpc = response.getOpc(0)
  if resOpc != expectedOpc:
    let errmsg = &"! {procName}: response OPC is mismatch, 0x{resOpc:04x}"
    syslog.error(errmsg)
    return
  let res = response.getLeInt16(2)
  result = some(res)

# ==============================================================================
# Instructions
# ==============================================================================

# ------------------------------------------------------------------------------
# 1.4.1 GATT 接続指示 (BT4.2)
# ------------------------------------------------------------------------------
proc gattCommonConnectIns*(self: BleClient, params: GattConnParams):
    Future[Option[int16]] {.async.} =
  const
    procName = "gattCommonConnectIns"
    indOpc = BTM_D_OPC_BLE_GATT_CMN_CONNECT_INS
    expectedOpc = BTM_D_OPC_BLE_GATT_CMN_CONNECT_CFM
  var buf = newSeq[uint8](27)
  buf.setOpc(0, indOpc)
  buf[2] = (if params.filterPolicy: 1 else: 0).uint8
  let connparam = params.phys[Phy1M]
  setLe16(buf, 2, connparam.scanInterval)
  setLe16(buf, 4, connparam.scanWindow)
  buf[6] = params.peer.addrType.uint8
  buf.setBdAddr(7, params.peer.address)
  buf[13] = params.ownAddrType.uint8
  buf[14] = params.randomAddrType.uint8
  setLe16(buf, 15, connparam.conIntervalMin)
  setLe16(buf, 17, connparam.conIntervalMax)
  setLe16(buf, 19, connparam.conLatency)
  setLe16(buf, 21, connparam.supervisionTimeout)
  setLe16(buf, 23, connparam.minCeLength)
  setLe16(buf, 25, connparam.maxCeLength)
  result = await self.btmInstruction(procName, buf.toString, expectedOpc)

# ------------------------------------------------------------------------------
# 1.4.5 GATT 切断指示
# ------------------------------------------------------------------------------
proc gattCommonDisconnectIns*(self: BleClient, gattId: uint16):
    Future[Option[int16]] {.async.} =
  const
    procName = "gattCommonDisconnectIns"
    indOpc = BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_INS
    expectedOpc = BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_CFM
  var buf: array[4, uint8]
  buf.setOpc(0, indOpc)
  buf.setLe16(2, gattId)
  result = await self.btmInstruction(procName, buf.toString, expectedOpc)

# ------------------------------------------------------------------------------
# 1.4.8 GATT 接続中断指示
# ------------------------------------------------------------------------------
proc gattCommonConnectCancelIns*(self: BleClient): Future[bool] {.async.} =
  const
    procName = "gattCommonConnectCancelIns"
    indOpc = BTM_D_OPC_BLE_GATT_CMN_CONNECT_CANCEL_INS
    expectedOpc = BTM_D_OPC_BLE_GATT_CMN_CONNECT_CANCEL_CFM
  var buf: array[2, uint8]
  buf.setOpc(0, indOpc)
  let res_opt = await self.btmSendRecv(buf.toString)
  if res_opt.isNone:
    let errmsg = &"! {procName}: failed"
    syslog.error(errmsg)
    return
  let response = res_opt.get()
  let resOpc = response.getOpc(0)
  if resOpc != expectedOpc:
    let errmsg = &"! {procName}: response OPC is mismatch, 0x{resOpc:04x}"
    syslog.error(errmsg)
    return
  let hciCode = response.getu8(2)
  self.debugEcho(&"* {procName}: hciCode: {hciCode}")
  result = hciCode.checkHciStatus(procName)

# ==============================================================================
# Instruction/Confirm -> Wait Event
# ==============================================================================

# ------------------------------------------------------------------------------
# GATT 接続
# ------------------------------------------------------------------------------
proc gattConnect*(self: BleClient, params: GattConnParams, timeout: int = 0):
    Future[Option[GattClient]] {.async.} =
  const procName = "gattConnect"
  let gattRes_opt = await self.gattCommonConnectIns(params)
  if gattRes_opt.isNone:
    syslog.error(&"! {procName}: GATT connection failed.")
    return
  let gattRes = gattRes_opt.get()
  if gattRes != 0:
    let errmsg = gattResultToString(gattRes, detail = true)
    syslog.error(&"! {procName}: GATT connection failed, {errmsg}.")
    return
  var
    gattId: Option[uint16]
    conHandle: Option[uint16]
  const waitingEvents = @[
    BTM_D_OPC_BLE_GAP_CONNECTION_COMPLETE_EVT,
    BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT,
  ]
  while true:
    let payload_opt = await self.waitAppEvent(waitingEvents, timeout)
    if payload_opt.isNone:
      # timeouted
      syslog.error(&"! {procName}: GATT connection timeouted.")
      discard await self.gattCommonConnectCancelIns()
      break
    let msg_opt = payload_opt.get.parseEvent()
    if msg_opt.isNone:
      continue
    let msg = msg_opt.get()
    case msg.event:
    of GapConenctionComplete:
      # LE Connection Complete 通知
      conHandle = some(msg.leConData.conHandle)
    of GattCmnConnect:
      # GATT 接続通知
      let gattResult = msg.gattConData.common.gattResult
      if gattResult == 0:
        gattId = some(msg.gattConData.common.gattId)
      else:
        logGattResult(procName, gattResult, detail = true)
        break
    else:
      discard
    if gattId.isSome and conHandle.isSome:
      # 2つの通知受信完了
      let client_opt = self.newGattClient(gattId.get, conhandle.get)
      if client_opt.isSome:
        let client = client_opt.get()
        client.peer = params.peer
        result = some(client)
      break
  discard await self.waitAppEvent(@[])

# ------------------------------------------------------------------------------
# Disconnect
# ------------------------------------------------------------------------------
proc disconnect*(self: GattClient): Future[bool] {.async.} =
  let gattId = self.gattId
  let res_opt = await self.bleClient.gattCommonDisconnectIns(gattId)
  if res_opt.isNone:
    return
  result = self.bleClient.deregister(self)
