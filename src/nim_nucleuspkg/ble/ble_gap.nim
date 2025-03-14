import std/asyncdispatch
import ./ble_client
import ./core/hci_status
import ./core/opc
import ./gap/types
import ./gap/parsers
from ./gatt/types import ConnParams
import ./util
export types, parsers

# ==============================================================================
# Requests
# ==============================================================================

# ------------------------------------------------------------------------------
# 1.2.11 LE Set Scan Parameters 要求
# ------------------------------------------------------------------------------
proc setScanParametersReq*(self: BleClient, scanType: ScanType, scanInterval: uint16 = 0x0060,
    scanWindow: uint16 = 0x0030, ownAddrType: AddrType, ownRandomAddrType: RandomAddrType,
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

# ------------------------------------------------------------------------------
# 1.2.20 LE Read White List Size 要求
# ------------------------------------------------------------------------------
proc readWhiteListSizeReq*(self: BleClient): Future[int] {.async.} =
  const
    procName = "readWhiteListSizeReq"
    reqOpc = BTM_D_OPC_BLE_GAP_READ_WHITE_LIST_SIZE_REQ
    expOpc = BTM_D_OPC_BLE_GAP_READ_WHITE_LIST_SIZE_RSP
  var buf: array[2, uint8]
  buf.setOpc(0, reqOpc)
  let res = await self.btmRequestResponse(procName, buf.toString, expOpc)
  if res.result and res.payload.len == 1:
    let size = res.payload.getU8(0)
    result = size.int

# ------------------------------------------------------------------------------
# 1.2.22 LE Clear White List 要求
# ------------------------------------------------------------------------------
proc clearWhiteListReq*(self: BleClient): Future[bool] {.async.} =
  const
    procName = "clearWhiteListSizeReq"
    reqOpc = BTM_D_OPC_BLE_GAP_CLEAR_WHITE_LIST_REQ
    expOpc = BTM_D_OPC_BLE_GAP_CLEAR_WHITE_LIST_RSP
  var buf: array[2, uint8]
  buf.setOpc(0, reqOpc)
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ------------------------------------------------------------------------------
# 1.2.24 LE Add Device To White List 要求
# ------------------------------------------------------------------------------
proc addDeviceToWhiteListReq*(self: BleClient, peer: PeerAddr): Future[bool] {.async.} =
  const
    procName = "addDeviceToWhiteListSizeReq"
    reqOpc = BTM_D_OPC_BLE_GAP_ADD_DEVICE_TO_WHITE_LIST_REQ
    expOpc = BTM_D_OPC_BLE_GAP_ADD_DEVICE_TO_WHITE_LIST_RSP
  var buf: array[9, uint8]
  buf.setOpc(0, reqOpc)
  buf[2] = peer.addrType.uint8
  buf.setBdAddr(3, peer.address)
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ------------------------------------------------------------------------------
# 1.2.26 LE Remove Device From White List 要求
# ------------------------------------------------------------------------------
proc removeDeviceFromWhiteListReq*(self: BleClient, peer: PeerAddr): Future[bool] {.async.} =
  const
    procName = "removeDeviceFromWhiteListSizeReq"
    reqOpc = BTM_D_OPC_BLE_GAP_REMOVE_DEVICE_FROM_WHITE_LIST_REQ
    expOpc = BTM_D_OPC_BLE_GAP_REMOVE_DEVICE_FROM_WHITE_LIST_RSP
  var buf: array[9, uint8]
  buf.setOpc(0, reqOpc)
  buf[2] = peer.addrType.uint8
  buf.setBdAddr(3, peer.address)
  result = await self.btmRequest(procName, buf.toString, expOpc)

# ------------------------------------------------------------------------------
# 1.2.28 LE Connection Update 指示->確認->通知
# ------------------------------------------------------------------------------
proc gapConnectionUpdate*(self: BleClient, conHandle: uint16, params: ConnParams):
    Future[bool] {.async.} =
  const
    procName = "gapConnectionUpdate"
    insOpc = BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_INS
    cfmOpc = BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_CFM
    #evtOpc = BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_EVT
  var buf: array[16, uint8]
  buf.setOpc(0, insOpc)
  buf.setLe16(2, conHandle)
  buf.setLe16(4, params.conIntervalMin)
  buf.setLe16(6, params.conIntervalMax)
  buf.setLe16(8, params.conLatency)
  buf.setLe16(10, params.supervisionTimeout)
  buf.setLe16(12, params.minCeLength)
  buf.setLe16(14, params.maxCeLength)
  result = await self.btmRequest(procName, buf.toString, cfmOpc)

# ==============================================================================
# Instructs
# ==============================================================================

# ------------------------------------------------------------------------------
# 1.2.17 LE Disconnect 指示
# ------------------------------------------------------------------------------
proc disconnectIns*(self: BleClient, conHandle: uint16, reason: HciStatus):
    Future[bool] {.async.} =
  const
    procName = "setScanParametersReq"
    reqOpc = BTM_D_OPC_BLE_GAP_DISCONNECT_INS
    expOpc = BTM_D_OPC_BLE_GAP_DISCONNECT_CFM
  var buf: array[5, uint8]
  buf.setOpc(0, reqOpc)
  buf.setLe16(2, conHandle)
  buf[4] = reason.uint8
  result = await self.btmRequest(procName, buf.toString, expOpc)
