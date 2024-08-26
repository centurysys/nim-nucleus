import std/asyncdispatch
import std/options
import std/strformat
import std/strutils
import nim_nucleus/submodule
import nim_nucleus/ble/util

proc eventHandler(self: BleClient) {.async.} =
  while true:
    let msg = await self.waitEvent()
    echo &"* Event: {msg.hexDump}"
    let event_opt = msg.parseEvent()
    if event_opt.isSome:
      let event = event_opt.get()
      echo &"* OPC: {event.opc:04X}"

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
      if report.name.isSome:
        echo &"* name: {report.name.get}"
      echo &"* RSSI: {report.rssi} [dBm]"

proc connection(self: BleClient, peerAddr: string):
    Future[Option[GattClient]] {.async.} =
  let peer_opt = peerAddr.string2bdAddr()
  if peer_opt.isNone:
    return
  let peer = peer_opt.get()
  let gattParams = gattDefaultGattConnParams(peer, random = false)
  let client_opt = await self.gattConnect(gattParams, timeout = 2000)
  if client_opt.isNone:
    echo "GATT connection failed."
    discard await self.gattCommonConnectCancelIns()
    return
  let client = client_opt.get()
  echo &"GATT connected, gattID: 0x{client.gattId:04x}, conHandle: 0x{client.conHandle:04x}"
  result = some(client)

proc sensorTag(self: GattClient) {.async.} =
  let mtu_opt = await self.gattExchangeMtu()
  if mtu_opt.isSome:
    echo &"*** MTU: {mtu_opt.get()}"
  let primaryServices = await self.gattAllPrimaryServices()
  if primaryServices.isSome:
    let services = primaryServices.get().services
    echo &"*** Primary Services: {services.len}"
    for service in services:
      echo service
  block:
    let allCharacteristics = await self.gattAllCharacteristicsOfService(
      0x0001'u16, 0x0007'u16)
    if allCharacteristics.isSome:
      let characteristics = allCharacteristics.get().characteristics
      echo "*** All Characteristics of a Service"
      for characteristic in characteristics:
        echo characteristic
  block:
    let uuid = Uuid(uuidType: Uuid16, uuid16: [0x00, 0x2a])
    let allCharacteristics = await self.gattDiscoverCharacteristicsByUuid(
      0x0001'u16, 0x0007'u16, uuid)
    if allCharacteristics.isSome:
      let characteristics = allCharacteristics.get().characteristics
      echo "*** Characteristics By UUID"
      for characteristic in characteristics:
        echo characteristic
  let res = await self.disconnect()
  echo &" disconnect/deregister -> result: {res}"

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
    let res = await ble.setScanParametersReq(ScanType.Passive,
        ownAddrType = AddrType.Public, ownRandomAddrType = RandomAddrType.Static)
    echo &"setScanParametersReq -> {res}"
  block:
    let res = await ble.setScanEnableReq(scanEnable = true)
    echo &"setScanEnableReq -> {res}"
  await sleepAsync(200)
  block:
    let client_opt = await ble.connection("C4:BE:84:70:09:00")
    if client_opt.isSome:
      let client = client_opt.get()
      asyncCheck client.sensorTag()
  for wait in 0 ..< 30:
    await sleepAsync(1000)
  block:
    let res = await ble.setScanEnableReq(scanEnable = false)
    stderr.write(&"setScanEnableReq -> {res}\n")

  quit(0)
