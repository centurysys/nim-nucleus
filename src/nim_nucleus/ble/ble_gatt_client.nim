import std/asyncdispatch
import std/options
import ../lib/asyncsync
import ./core/gatt_result
import ./core/opc
import ./gatt/parsers
import ./ble_client
import ./util

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setOpcGattId(self: GattClient, buf: var openArray[char|uint8], opc: uint16) =
  buf.setOpc(0, opc)
  buf.setLe16(2, self.gattId)

# ------------------------------------------------------------------------------
# 1.5.1: GATT Exchange MTU 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattExchangeMtu*(self: GattClient): Future[Option[uint16]] {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT
  var buf: array[4, uint8]
  self.setOpcGattId(buf, insOpc)
  let res_opt = await self.gattSendRecv(buf.toString, cfmOpc, evtOpc)
  if res_opt.isNone:
    return
  let payload = res_opt.get()
  let mtuInfo_opt = payload.parseGattExchangeMtu()
  if mtuInfo_opt.isSome:
    result = some(mtuInfo_opt.get.serverMtu)
