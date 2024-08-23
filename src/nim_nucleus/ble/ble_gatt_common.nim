import std/asyncdispatch
import std/options
import std/strformat
import std/tables
import ./ble_client
import ./ble_gap
import ./notifications
import ./core/opc
import ./core/gatt_result
import ./gatt/requests
import ./gatt/types
import ./util
import ../lib/asyncsync
import ../lib/syslog
export types

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
  let res = getLeInt16(payload, 2)
  result = some(res)

# ==============================================================================
# Instructions
# ==============================================================================

# ------------------------------------------------------------------------------
# 1.4.2 GATT 接続指示
# ------------------------------------------------------------------------------
proc gattCommonConnectIns*(self: BleClient, params: GattConnParams):
    Future[Option[int16]] {.async.} =
  const
    procName = "gattCommonConnectIns"
    indOpc = BTM_D_OPC_BLE_GATT_CMN_CONNECT_INS
    expectedOpc = BTM_D_OPC_BLE_GATT_CMN_CONNECT_CFM
  let phyNums = params.phys.len
  if phyNums == 0 or phyNums > 3:
    return
  let pktlen = 13 + 16 * phyNums
  var buf = newSeqOfCap[uint8](pktlen)
  buf.setOpc(0, indOpc)
  buf[2] = (if params.filterPolicy: 1 else: 0).uint8
  buf[3] = params.ownAddrType.uint8
  buf[4] = params.randomAddrType.uint8
  buf[5] = params.peer.addrType.uint8
  buf.setBdAddr(6, params.peer.address)
  var
    phys: uint8
    pos = 13
  for phy in [Phy1M, Phy2M, PhyCoded]:
    if params.phys.hasKey(phy):
      phys = phys or phy.uint8
      let connparam = params.phys[phy]
      setLe16(buf, pos, connparam.scanInterval)
      setLe16(buf, pos + 2, connparam.scanWindow)
      setLe16(buf, pos + 4, connparam.conIntervalMin)
      setLe16(buf, pos + 6, connparam.conIntervalMax)
      setLe16(buf, pos + 8, connparam.conLatency)
      setLe16(buf, pos + 10, connparam.supervisionTimeout)
      setLe16(buf, pos + 12, connparam.minCeLength)
      setLe16(buf, pos + 14, connparam.maxCeLength)
      pos.inc(16)
  buf[12] = phys
  result = await self.btmInstruction(procName, buf.toString, expectedOpc)

# ------------------------------------------------------------------------------
# 1.4.5 GATT 切断指示
# ------------------------------------------------------------------------------
proc gattCommonDisconnectIns*(self: BleClient, gattId: uint16): Future[Option[int16]]
    {.async.} =
  const
    procName = "gattCommonDisconnectIns"
    indOpc = BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_INS
    expectedOpc = BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_CFM
  var buf: array[4, uint8]
  buf.setOpc(0, indOpc)
  buf.setLe16(2, gattId)
  result = await self.btmInstruction(procName, buf.toString, expectedOpc)

# ==============================================================================
# Instruction/Confirm -> Wait Event
# ==============================================================================

# ------------------------------------------------------------------------------
# GATT 接続
# ------------------------------------------------------------------------------
proc gattConnect*(self: BleClient, params: GattConnParams): Future[Option[GattClient]]
    {.async.} =
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
    mtu: Option[uint16]
    alg: Option[ChannSelAlgorithm]
  while true:
    let payload = await self.waitResponse()
    let msg_opt = payload.parseEvent()
    if msg_opt.isNone:
      continue
    let msg = msg_opt.get()
    case msg.opc:
    of BTM_D_OPC_BLE_GAP_ENHANCED_CONNECTION_COMPLETE_EVT:
      # LE Enhanced Connection Complete 通知
      conHandle = some(msg.leConData.conHandle)
    of BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT:
      # GATT 接続通知
      let gattResult = msg.gattConData.common.gattResult
      if gattResult == 0:
        gattId = some(msg.gattConData.common.gattId)
      else:
        logGattResult(procName, gattResult, detail = true)
        break
    of BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT:
      # Gatt Exchange MTU 通知
      mtu = some(msg.gattExchangeMtuData.serverMtu)
    of BTM_D_OPC_BLE_GAP_CHANNEL_SELECTION_ALGORITHM_EVT:
      # LE Channel Selection Algorithm 通知
      alg = some(msg.leChanAlgData.alg)
    else:
      discard
    if gattId.isSome and conHandle.isSome and mtu.isSome and alg.isSome:
      # 4つの通知受信完了
      let client = new GattClient
      client.ble = addr self
      client.gattId = gattId.get()
      client.conHandle = conHandle.get()
      client.mtu = mtu.get()
      result = some(client)
      break
