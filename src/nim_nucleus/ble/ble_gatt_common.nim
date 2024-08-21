import std/asyncdispatch
import std/options
import std/strformat
import std/tables
import ./ble_client
import ./core/opc
import ./gatt/requests
import ./gatt/types
import ./util
import ../lib/syslog
export types

# ==============================================================================
# Common functions
# ==============================================================================

# ------------------------------------------------------------------------------
# API: Send Indication/Receive Confirmation
# ------------------------------------------------------------------------------
proc btmIndication*(self: BleClient, procName: string, payload: string,
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
# Indications
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
  buf[5] = params.peerAddrType.uint8
  buf.setBdAddr(6, params.peerAddr)
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
  let gattRes = await self.btmIndication(procName, buf.toString, expectedOpc)
  result = gattRes

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
  result = await self.btmIndication(procName, buf.toString, expectedOpc)

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
