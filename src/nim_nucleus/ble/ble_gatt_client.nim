import std/asyncdispatch
import std/options
import std/strformat
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

# ------------------------------------------------------------------------------
# 1.5.4: GATT All Primary Services 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattAllPrimaryServices*(self: GattClient): Future[Option[GattAllPrimaryServices]]
    {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_ALL_PRIMARY_SERVICES_EVT
    endOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_EVT
  var buf: array[4, uint8]
  self.setOpcGattId(buf, insOpc)
  let confirmed = await self.gattSend(buf.toString, cfmOpc)
  if not confirmed:
    return
  var res: GattAllPrimaryServices
  while true:
    let response = await self.waitEvent(timeout = 1000)
    if response.isNil:
      return
    let opc = response.payload.getOpc()
    case opc
    of evtOpc:
      let services_opt = response.payload.parseGattAllPrimaryServices()
      if services_opt.isSome:
        res.services.add(services_opt.get.services)
    of endOpc:
      break
    else:
      discard
  result = some(res)

# ------------------------------------------------------------------------------
# 1.5.26: GATT All Characteristic Descriptors 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattAllCharacteristicDescriptors*(self: GattClient, startHandle: uint16,
    endHandle: uint16): Future[Option[GattAllCharacteristicDescriptors]] {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_ALL_CHARACTERISTIC_DESCRIPTORS_EVT
    endOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_EVT
  var buf: array[8, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, startHandle)
  buf.setLe16(6, endHandle)
  let confirmed = await self.gattSend(buf.toString, cfmOpc)
  if not confirmed:
    return
  var res: GattAllCharacteristicDescriptors
  while true:
    let response = await self.waitEvent(timeout = 1000)
    if response.isNil:
      return
    let opc = response.payload.getOpc()
    case opc
    of evtOpc:
      let services_opt = response.payload.parseGattAllCharacteristicDescriptors()
      if services_opt.isSome:
        echo "** parse Characteristic OK!"
        res.characteristics.add(services_opt.get.characteristics)
      else:
        echo "!! parse Characteristic failed."
    of endOpc:
      break
    else:
      discard
  result = some(res)
