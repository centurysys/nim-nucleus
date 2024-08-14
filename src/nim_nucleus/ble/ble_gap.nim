import std/asyncdispatch
import ./ble_client
import ./core/opc
import ./gap/types
import ./util
export types

# ------------------------------------------------------------------------------
# 1.2.11 LE Set Scan Parameters 要求
# ------------------------------------------------------------------------------
proc setScanParametersReq*(self: BleClient, scanType: ScanType, scanInterval: uint16,
    scanWindow: uint16, ownAddrType: AddrType, ownRandomAddrType: RandomAddrType,
    filterPolicy: ScanFilterPolicy): Future[bool] {.async.} =
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
