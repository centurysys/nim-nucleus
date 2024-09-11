import std/asyncdispatch
import std/options
import std/strformat
import results
import ./core/gatt_result
import ./core/opc
import ./gatt/parsers
import ./gatt/types
import ./ble_client
import ./util
import ../lib/errcode
import ../lib/syslog
export results
export types, gatt_result, parsers, errcode

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc setOpcGattId(self: GattClient, buf: var openArray[char|uint8], opc: uint16) =
  buf.setOpc(0, opc)
  buf.setLe16(2, self.gattId)

# ------------------------------------------------------------------------------
# 1.5.1: GATT Exchange MTU 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattExchangeMtu*(self: GattClient): Future[Result[uint16, ErrorCode]] {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT
  var buf: array[4, uint8]
  self.setOpcGattId(buf, insOpc)
  let payload_res = await self.gattSendRecv(buf.toString, cfmOpc, evtOpc)
  if payload_res.isErr:
    return err(payload_res.error)
  let payload = payload_res.get()
  let mtuInfo_opt = payload.parseGattExchangeMtu()
  if mtuInfo_opt.isSome:
    result = ok(mtuInfo_opt.get.serverMtu)

# ------------------------------------------------------------------------------
# 1.5.4: GATT All Primary Services 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattAllPrimaryServices*(self: GattClient): Future[Result[GattAllPrimaryServices, ErrorCode]]
    {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_ALL_PRIMARY_SERVICES_EVT
    endOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_EVT
  var buf: array[4, uint8]
  self.setOpcGattId(buf, insOpc)
  let confirmed_res = await self.gattSend(buf.toString, cfmOpc)
  if confirmed_res.isErr:
    return err(confirmed_res.error)
  let confirmed = confirmed_res.get()
  if not confirmed:
    return
  var res: GattAllPrimaryServices
  while true:
    let response_res = await self.waitEvent(timeout = 30 * 1000)
    if response_res.isErr:
      if response_res.error == ErrorCode.Disconnected:
        return err(ErrorCode.Disconnected)
      else:
        break
    let response = response_res.get()
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
  if res.services.len > 0:
    result = ok(res)

# ------------------------------------------------------------------------------
# 1.5.16: GATT All Characteristics of a Service 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattAllCharacteristicsOfService*(self: GattClient, startHandle: uint16,
    endHandle: uint16): Future[Result[GattCharacteristicsOfService, ErrorCode]] {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_ALL_CHARACTERISTICS_OF_A_SERVICE_EVT
    endOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_EVT
  var buf: array[8, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, startHandle)
  buf.setLe16(6, endHandle)
  let confirmed_res = await self.gattSend(buf.toString, cfmOpc)
  if confirmed_res.isErr:
    return err(confirmed_res.error)
  let confirmed = confirmed_res.get()
  if not confirmed:
    return
  var res: GattCharacteristicsOfService
  while true:
    let response_res = await self.waitEvent(timeout = 30 * 1000)
    if response_res.isErr:
      if response_res.error == ErrorCode.Disconnected:
        return err(ErrorCode.Disconnected)
      else:
        break
    let response = response_res.get()
    let opc = response.payload.getOpc()
    case opc
    of evtOpc:
      let services_opt = response.payload.parseGattCharacteristicOfService()
      if services_opt.isSome:
        res.characteristics.add(services_opt.get.characteristics)
    of endOpc:
      break
    else:
      discard
  if res.characteristics.len > 0:
    result = ok(res)

# ------------------------------------------------------------------------------
# 1.5.20: GATT Discover Characteristics by UUID 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattDiscoverCharacteristicsByUuid*(self: GattClient, startHandle: uint16,
    endHandle: uint16, uuid: Uuid): Future[Result[GattCharacteristicsOfService, ErrorCode]]
    {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_CHARACTERISTICS_BY_UUID_EVT
    endOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_EVT
  var buf: array[25, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, startHandle)
  buf.setLe16(6, endHandle)
  buf.setUuid(8, uuid)
  let confirmed_res = await self.gattSend(buf.toString, cfmOpc)
  if confirmed_res.isErr:
    return err(confirmed_res.error)
  let confirmed = confirmed_res.get()
  if not confirmed:
    return
  var res: GattCharacteristicsOfService
  while true:
    let response_res = await self.waitEvent(timeout = 30 * 1000)
    if response_res.isErr:
      if response_res.error == ErrorCode.Disconnected:
        return err(ErrorCode.Disconnected)
      else:
        break
    let response = response_res.get()
    let opc = response.payload.getOpc()
    case opc
    of evtOpc:
      let services_opt = response.payload.parseGattCharacteristicOfService()
      if services_opt.isSome:
        res.characteristics.add(services_opt.get.characteristics)
    of endOpc:
      break
    else:
      discard
  if res.characteristics.len > 0:
    result = ok(res)

# ------------------------------------------------------------------------------
# 1.5.24: GATT All Characteristic Descriptors 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattAllCharacteristicDescriptors*(self: GattClient, startHandle: uint16,
    endHandle: uint16): Future[Result[GattAllCharacteristicDescriptors, ErrorCode]]
    {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_ALL_CHARACTERISTIC_DESCRIPTORS_EVT
    endOpc = BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_EVT
  var buf: array[8, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, startHandle)
  buf.setLe16(6, endHandle)
  let confirmed_res = await self.gattSend(buf.toString, cfmOpc)
  if confirmed_res.isErr:
    return err(confirmed_res.error)
  let confirmed = confirmed_res.get()
  if not confirmed:
    return
  var res: GattAllCharacteristicDescriptors
  while true:
    let response_res = await self.waitEvent(timeout = 30 * 1000)
    if response_res.isErr:
      if response_res.error == ErrorCode.Disconnected:
        return err(ErrorCode.Disconnected)
      else:
        break
    let response = response_res.get()
    let opc = response.payload.getOpc()
    case opc
    of evtOpc:
      let services_opt = response.payload.parseGattAllCharacteristicDescriptors()
      if services_opt.isSome:
        res.characteristics.add(services_opt.get.characteristics)
    of endOpc:
      break
    else:
      discard
  result = ok(res)

# ------------------------------------------------------------------------------
# 1.5.28: GATT Read Characteristic Value 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattReadCharacteristicValue*(self: GattClient, handle: uint16):
    Future[Result[seq[uint8], ErrorCode]] {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_EVT
  var buf: array[6, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, handle)
  let response_res = await self.gattSendRecv(buf.toString, cfmOpc, evtOpc)
  if response_res.isErr:
    return err(response_res.error)
  let response = response_res.get()
  let res_opt = response.parseGattReadCharacteristicValue()
  if res_opt.isNone:
    return err(ErrorCode.ParseError)
  result = ok(res_opt.get.value)

# ------------------------------------------------------------------------------
# 1.5.31: GATT Read Using Characteristic UUID 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattReadUsingCharacteristicUuid*(self: GattClient, startHandle: uint16,
    endHandle: uint16, uuid: Uuid): Future[Result[seq[HandleValue], ErrorCode]]
    {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_EVT
  var buf: array[25, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, startHandle)
  buf.setLe16(6, endHandle)
  buf.setUuid(8, uuid)
  let response_res = await self.gattSendRecv(buf.toString, cfmOpc, evtOpc)
  if response_res.isErr:
    return err(response_res.error)
  let response = response_res.get()
  let res_opt = response.parseGattReadUsingCharacteristicUuid()
  if res_opt.isNone:
    return err(ErrorCode.ParseError)
  result = ok(res_opt.get.values)

# ------------------------------------------------------------------------------
# 1.5.40: GATT Read Characteristic Descriptors 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattReadCharacteristicDescriptors*(self: GattClient, handle: uint16):
    Future[Result[seq[uint8], ErrorCode]] {.async.} =
  const
    insOpc = BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_EVT
  var buf: array[6, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, handle)
  let response_res = await self.gattSendRecv(buf.toString, cfmOpc, evtOpc)
  if response_res.isErr:
    return err(response_res.error)
  let response = response_res.get()
  let res_opt = response.parseGattReadCharacteristicDescriptors()
  if res_opt.isNone:
    return err(ErrorCode.ParseError)
  result = ok(res_opt.get.descs)

# ------------------------------------------------------------------------------
# 1.5.52: GATT Write Characteristic Value 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattWriteCharacteristicValue*(self: GattClient, handle: uint16,
    value: seq[uint8|char]|string): Future[Result[bool, ErrorCode]] {.async.} =
  const
    procName = "gattWriteCharacteristicValue"
    insOpc = BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_EVT
  var buf: array[520, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, handle)
  buf.setLe16(6, value.len.uint16)
  copyMem(addr buf[8], addr value[0], value.len)
  let response_res = await self.gattSendRecv(buf.toString, cfmOpc, evtOpc)
  if response_res.isErr:
    return err(response_res.error)
  let response = response_res.get()
  let res = response.parseGattEventCommon()
  if res.gattResult != 0:
    logGattResult(procName, res.gattResult, detail = true)
    result = err(ErrorCode.GattError)
  else:
    result = ok(true)

# ------------------------------------------------------------------------------
# 1.5.64: GATT Write Characteristic Descriptors 指示->確認->通知
# ------------------------------------------------------------------------------
proc gattWriteCharacteristicDescriptors*(self: GattClient, handle: uint16,
    descs: seq[uint8|char]|string): Future[Result[bool, ErrorCode]] {.async.} =
  const
    procName = "gattWriteCharacteristicDescriptors"
    insOpc = BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_INS
    cfmOpc = BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_CFM
    evtOpc = BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_EVT
  var buf: array[520, uint8]
  self.setOpcGattId(buf, insOpc)
  buf.setLe16(4, handle)
  buf.setLe16(6, descs.len.uint16)
  copyMem(addr buf[8], addr descs[0], descs.len)
  let response_res = await self.gattSendRecv(buf.toString, cfmOpc, evtOpc)
  if response_res.isErr:
    return err(response_res.error)
  let response = response_res.get()
  let res = response.parseGattEventCommon()
  if res.gattResult != 0:
    logGattResult(procName, res.gattResult, detail = true)
    result = err(ErrorCode.GattError)
  else:
    result = ok(true)

# ==============================================================================
# Helper functions
# ==============================================================================

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattReadUsingCharacteristicUuid*(self: GattClient, startHandle: uint16,
    endHandle: uint16, uuidStr: string): Future[Result[seq[HandleValue], ErrorCode]]
    {.async.} =
  let uuid_opt = uuidStr.str2uuid()
  if uuid_opt.isNone:
    let errmsg = &"! gattReadUsingCharacteristicUuid: invalid UUID: {uuidStr}"
    syslog.error(errmsg)
    return err(ErrorCode.ValueError)
  let uuid = uuid_opt.get()
  result = await self.gattReadUsingCharacteristicUuid(startHandle, endHandle, uuid)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattWriteCharacteristicValue*(self: GattClient, handle: uint16,
    value: uint16): Future[Result[bool, ErrorCode]] {.async.} =
  var buf = newSeq[uint8](2)
  buf.setLe16(0, value)
  result = await self.gattWriteCharacteristicValue(handle, buf)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattWriteCharacteristicValue*(self: GattClient, handle: uint16,
    value: uint8): Future[Result[bool, ErrorCode]] {.async.} =
  var buf = newSeq[uint8](1)
  buf[0] = value
  result = await self.gattWriteCharacteristicValue(handle, buf)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattWriteCharacteristicDescriptors*(self: GattClient, handle: uint16,
    descs: uint16): Future[Result[bool, ErrorCode]] {.async.} =
  var buf = newSeq[uint8](2)
  buf.setLe16(0, descs)
  result = await self.gattWriteCharacteristicDescriptors(handle, buf)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattWriteCharacteristicDescriptors*(self: GattClient, handle: uint16,
    descs: uint8): Future[Result[bool, ErrorCode]] {.async.} =
  var buf = newSeq[uint8](1)
  buf[0] = descs
  result = await self.gattWriteCharacteristicDescriptors(handle, buf)
