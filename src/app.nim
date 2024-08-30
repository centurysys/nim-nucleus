import std/asyncdispatch
import std/options
import std/strformat
import std/strutils
import nim_nucleus/submodule
import nim_nucleus/ble/util

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc eventHandler(self: BleClient) {.async.} =
  while true:
    let msg = await self.waitEvent()
    echo &"* Event: {msg.hexDump}"
    let event_opt = msg.parseEvent()
    if event_opt.isSome:
      let event = event_opt.get()
      echo &"* OPC: {event.opc:04X}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc advertisingHandler(self: BleClient) {.async.} =
  while true:
    let msg = await self.waitAdvertising()
    echo &"* Advertising: {msg.hexDump}"
    let event_opt = msg.parseEvent()
    if event_opt.isSome:
      let event = event_opt.get()
      let report = event.advData
      echo &"* eventType: {report.eventType}"
      echo &"* addrType:  {report.peer.addrType}"
      echo &"* bdAddr: {report.peer.address.bdAddr2string}"
      if report.flags.isSome:
        echo &"* flags: 0x{report.flags.get:02x}"
      if report.name.isSome:
        echo &"* name: {report.name.get}"
      echo &"* RSSI: {report.rssi} [dBm]"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc connection(self: BleClient, peerAddr: string, random = false,
    timeout = 10 * 1000): Future[Option[GattClient]] {.async.} =
  let peer_opt = peerAddr.string2bdAddr()
  if peer_opt.isNone:
    return
  let peer = peer_opt.get()
  let gattParams = gattDefaultGattConnParams(peer, random = random)
  let client_opt = await self.gattConnect(gattParams, timeout = timeout)
  if client_opt.isNone:
    echo "Timeouted? GATT connection failed."
    discard await self.gattCommonConnectCancelIns()
    return
  let client = client_opt.get()
  echo &"GATT connected, gattID: 0x{client.gattId:04x}, conHandle: 0x{client.conHandle:04x}"
  result = some(client)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc notificationHandler(self: GattClient) {.async.} =
  while true:
    let msg = await self.waitNotify()
    echo &"* Notify received: handle: {msg.handle:04x}"
    echo msg.values.hexDump()

# ------------------------------------------------------------------------------
# TI SensorTag
# ------------------------------------------------------------------------------
proc sensorTag(self: GattClient) {.async.} =
  asyncCheck self.notificationHandler()
  let mtu_opt = await self.gattExchangeMtu()
  if mtu_opt.isSome:
    echo &"*** MTU: {mtu_opt.get()}"
  when true:
    let primaryServices = await self.gattAllPrimaryServices()
    if primaryServices.isSome:
      let services = primaryServices.get().services
      echo &"*** Primary Services: {services.len}"
      for service in services:
        echo service
  when true:
    let allCharacteristics = await self.gattAllCharacteristicsOfService(
      0x0001'u16, 0x00ff'u16)
    if allCharacteristics.isSome:
      let characteristics = allCharacteristics.get().characteristics
      echo "*** All Characteristics of a Service"
      for characteristic in characteristics:
        echo characteristic
  when true:
    for handle in ["2a00", "2a04"]:
      let handleValues_opt = await self.gattReadUsingCharacteristicUuid(0x0001'u16,
          0xffff'u16, handle)
      if handleValues_opt.isSome:
        let handleValues = handleValues_opt.get()
        for entry in handleValues:
          echo &"* handle: 0x{entry.handle:04x} -> value: \"{entry.value.toString}\""
  when false:
    #let uuid = Uuid(uuidType: Uuid16, uuid16: [0x00, 0x2a])
    let uuid = str2uuid("2a00").get()
    let allCharacteristics = await self.gattDiscoverCharacteristicsByUuid(
      0x0001'u16, 0x0007'u16, uuid)
    if allCharacteristics.isSome:
      let characteristics = allCharacteristics.get().characteristics
      echo "*** Characteristics By UUID"
      for characteristic in characteristics:
        echo characteristic
  block:
    let descs = await self.gattAllCharacteristicDescriptors(0x0020'u16, 0x0027'u16)
    if descs.isSome:
      for characteristic in descs.get.characteristics:
        echo characteristic
  block:
    discard await self.gattWriteCharacteristicValue(0x0024'u16, 0x01'u8)
    let onoff = await self.gattReadCharacteristicValue(0x0024)
    if onoff.isSome:
      echo &"on/off: {onoff.get}"
    discard await self.gattWriteCharacteristicDescriptors(0x0022'u16, 0x0001'u16)
    let cfg = await self.gattReadCharacteristicDescriptors(0x0022)
    if cfg.isSome:
      echo &"cfg: {cfg.get}"
    await sleepAsync(1000)
    let val = await self.gattReadCharacteristicValue(0x0021)
    if val.isSome:
      echo &"value: {val.get}"
      await sleepAsync(5000)
    discard await self.gattWriteCharacteristicDescriptors(0x0022'u16, 0'u16)
    discard await self.gattWriteCharacteristicValue(0x0024'u16, 0'u8)
  let res = await self.disconnect()
  echo &" disconnect/deregister -> result: {res}"

# ------------------------------------------------------------------------------
# WitMotion WT901BLE
# ------------------------------------------------------------------------------
proc wt901ble(self: GattClient) {.async.} =
  asyncCheck self.notificationHandler()
  when true:
    let primaryServices = await self.gattAllPrimaryServices()
    if primaryServices.isSome:
      let services = primaryServices.get().services
      echo &"*** Primary Services: {services.len}"
      for service in services:
        echo service
  when true:
    let allCharacteristics = await self.gattAllCharacteristicsOfService(
      0x0001'u16, 0x00ff'u16)
    if allCharacteristics.isSome:
      let characteristics = allCharacteristics.get().characteristics
      echo "*** All Characteristics of a Service"
      for characteristic in characteristics:
        echo characteristic
  when true:
    let handleValues_opt = await self.gattReadUsingCharacteristicUuid(0x0001'u16,
        0xffff'u16, "2a00")
    if handleValues_opt.isSome:
      let handleValues = handleValues_opt.get()
      for entry in handleValues:
        echo &"* handle: 0x{entry.handle:04x} -> value: \"{entry.value.toString}\""
  block:
    let reqValue = @[0xff'u8, 0xaa'u8, 0x03'u8, 0x03'u8, 0x00'u8]
    discard await self.gattWriteCharacteristicValue(0x000e'u8, reqValue)
  block:
    discard await self.gattWriteCharacteristicDescriptors(0x000c'u16, 0x0001'u16)
    let cfg = await self.gattReadCharacteristicDescriptors(0x000c)
    if cfg.isSome:
      echo &"cfg: {cfg.get}"
      await sleepAsync(5000)
      discard await self.gattWriteCharacteristicDescriptors(0x000c'u16, 0x0000'u16)
  let res = await self.disconnect()
  echo &" disconnect/deregister -> result: {res}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc asyncMain*() {.async.} =
  let ble = newBleClient(true)
  asyncCheck ble.eventHandler()
  asyncCheck ble.advertisingHandler()
  block:
    let res = await ble.initBTM()
    if not res:
      return
  block:
    let res = await ble.setSecurityModeReq(SecurityMode.Level2)
    echo &"setSecurityModeReq -> {res}"
  block:
    let res = await ble.setLocalIoCapabilitiesReq(IoCap.NoInputNoOutput)
    echo &"setLocalIoCapabilitiesReq -> {res}"
  block:
    let res = await ble.setScanParametersReq(ScanType.Active,
        ownAddrType = AddrType.Public, ownRandomAddrType = RandomAddrType.Static)
    echo &"setScanParametersReq -> {res}"
  block:
    let res = await ble.setScanEnableReq(scanEnable = true, filterDuplicates = true)
    echo &"setScanEnableReq(Enable) -> {res}"
  # 10sec scan
  await sleepAsync(10 * 1000)
  block:
    let res = await ble.setScanEnableReq(scanEnable = false)
    echo &"setScanEnableReq(Disable) -> {res}"
  block:
    let res = await ble.setScanParametersReq(ScanType.Passive,
        ownAddrType = AddrType.Public, ownRandomAddrType = RandomAddrType.Static)
    echo &"setScanParametersReq -> {res}"
  block:
    let res = await ble.setScanEnableReq(scanEnable = true, filterDuplicates = true)
    echo &"setScanEnableReq(Enable) -> {res}"
  await sleepAsync(2 * 1000)

  when true:
    echo "------ start connecting to SensorTag..."
    let client_opt = await ble.connection("C4:BE:84:70:09:00")
    if client_opt.isSome:
      let client = client_opt.get()
      asyncCheck client.sensorTag()
  when false:
    for retry in 0 ..< 3:
      echo &"------ start connecting to WT901BLE58 [{retry}]..."
      let client_opt = await ble.connection("CC:C1:AA:20:0D:61", random = true)
      if client_opt.isSome:
        echo " ==> connected"
        let client = client_opt.get()
        asyncCheck client.wt901ble()
        break

  for wait in 0 ..< 30:
    await sleepAsync(1000)

  quit(0)
