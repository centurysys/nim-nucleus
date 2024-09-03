import std/asyncdispatch
import ./ble_client
import ./core/hci_status
import ./core/opc
import ./gap/types
import ./gap/parsers
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
