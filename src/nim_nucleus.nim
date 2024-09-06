import std/asyncdispatch
import std/json
import std/options
import std/sequtils
import std/strformat
import std/strutils
import std/tables
import std/times
import nim_nucleus/submodule
export SecurityMode, IoCap, PeerAddr
export HandleValue

type
  ScanState = object
    active: bool
    enable: bool
    filter: bool
  BleDeviceObj = object
    bdAddr*: PeerAddr
    bdAddrStr*: string
    name*: Option[string]
    rssi*: int8
    seenTime*: Time
    keys: RemoteCollectionKeys
  BleDevice* = ref BleDeviceObj
  DeviceWait = object
    waitDeviceQueue: Mailbox[BleDevice]
    fut_device: Future[Option[BleDevice]]
    waiting: bool
  BleNimObj = object
    ble: BleClient
    mode: SecurityMode
    iocap: IoCap
    running: bool
    scan: ScanState
    eventQueue: AsyncQueue[string]
    devices: Table[PeerAddr, BleDevice]
    waiter: DeviceWait
  BleNim* = ref BleNimObj
  GattObj = object
    gatt: GattClient
    peer: PeerAddr
  Gatt* = ref GattObj

# ==============================================================================
# Advertising
# ==============================================================================

# ------------------------------------------------------------------------------
# Handler: Advertising
# ------------------------------------------------------------------------------
proc advertisingHandler(self: BleNim) {.async.} =
  while true:
    let payload = await self.ble.waitAdvertising()
    let report_opt = payload.parseAdvertisingReport()
    if report_opt.isNone:
      continue
    let report = report_opt.get()
    let device = new BleDevice
    device.bdAddr = report.peer
    device.bdAddrStr = bdAddr2string(report.peer.address)
    device.name = report.name
    device.rssi = report.rssi
    device.seenTime = now().toTime
    self.devices[report.peer] = device
    if self.waiter.waiting and (not self.waiter.waitDeviceQueue.full):
      await self.waiter.waitDeviceQueue.put(device)

# ==============================================================================
# Event
# ==============================================================================

# ------------------------------------------------------------------------------
# SM: LE ローカルセキュリティ設定通知 保存
# ------------------------------------------------------------------------------
proc setLocalSecurityData(self: BleNim, localSecurity: LocalSecurity) =
  let peer = localSecurity.peer
  let device = self.devices.getOrDefault(peer)
  if not device.isNil:
    device.keys.auth = localSecurity.auth
    device.keys.encKeySize = localSecurity.encKeySize
    device.keys.authorized = localSecurity.authorization

# ------------------------------------------------------------------------------
# SM: LE LTK 受信通知 保存
# ------------------------------------------------------------------------------
proc setLtk(self: BleNim, peerLtk: LtkEvent) =
  let peer = peerLtk.peer
  let device = self.devices.getOrDefault(peer)
  if not device.isNil:
    device.keys.ltk = peerLtk.ltk

# ------------------------------------------------------------------------------
# SM: LE EDIV Rand 受信通知 保存
# ------------------------------------------------------------------------------
proc setEdivRand(self: BleNim, edivRand: EdivRandEvent) =
  let peer = edivRand.peer
  let device = self.devices.getOrDefault(peer)
  if not device.isNil:
    device.keys.ediv = edivRand.ediv
    device.keys.rand = edivRand.rand

# ------------------------------------------------------------------------------
# SM: LE IRK 受信通知 保存
# ------------------------------------------------------------------------------
proc setIrk(self: BleNim, peerIrk: IrkEvent) =
  let peer = peerIrk.peer
  let device = self.devices.getOrDefault(peer)
  if not device.isNil:
    device.keys.irk = peerIrk.irk

# ------------------------------------------------------------------------------
# SM: LE CSRK 受信通知 保存
# ------------------------------------------------------------------------------
proc setCsrk(self: BleNim, peerCsrk: CsrkEvent) =
  let peer = peerCsrk.peer
  let device = self.devices.getOrDefault(peer)
  if not device.isNil:
    device.keys.csrk = peerCsrk.csrk

# ------------------------------------------------------------------------------
# SM: LE 認証完了通知 保存
# ------------------------------------------------------------------------------
proc setAuthCompleted(self: BleNim, authComplete: AuthCompleteEvent) =
  let peer = authComplete.peer
  let device = self.devices.getOrDefault(peer)
  if not device.isNil:
    device.keys.valid = true
    device.keys.peer = peer
    device.keys.bdAddrStr = peer.address.bdAddr2string()

# ------------------------------------------------------------------------------
# Handler: GAP/SM Events
# ------------------------------------------------------------------------------
proc eventHandler(self: BleNim) {.async.} =
  while true:
    let payload = await self.ble.waitEvent()
    let notify_opt = payload.parseEvent()
    if notify_opt.isNone:
      continue
    let notify = notify_opt.get()
    let opc = notify.opc
    echo &"*** Event: OPC: [{opc:04X}]"
    case notify.opc
    of BTM_D_OPC_BLE_SM_LOCAL_SECURITY_PROPERTY_EVT:
      # LE ローカルセキュリティ設定通知
      let data = notify.localSecurityData
      self.setLocalSecurityData(data)
    of BTM_D_OPC_BLE_SM_LTK_RECEIVE_EVT:
      # LE LTK 受信通知
      let data = notify.peerLtkData
      self.setLtk(data)
    of BTM_D_OPC_BLE_SM_EDIV_RAND_RECEIVE_EVT:
      # LE EDIV Rand 受信通知
      let data = notify.peerEdivRandData
      self.setEdivRand(data)
    of BTM_D_OPC_BLE_SM_IRK_RECEIVE_EVT:
      # LE IRK 受信通知
      let data = notify.peerIrkData
      self.setIrk(data)
    of BTM_D_OPC_BLE_SM_CSRK_RECEIVE_EVT:
      # LE CSRK 受信通知
      let data = notify.peerCsrkData
      self.setCsrk(data)
    of BTM_D_OPC_BLE_SM_AUTHENTICATION_COMPLETE_EVT:
      # LE 認証完了通知
      let data = notify.authCompleteData
      self.setAuthCompleted(data)
    else:
      discard

# ------------------------------------------------------------------------------
# API: async initialization
# ------------------------------------------------------------------------------
proc init*(self: BleNim): Future[bool] {.async.} =
  if self.running:
    return true
  result = await self.ble.initBTM()
  if result:
    if not await self.ble.setSecurityModeReq(self.mode):
      syslog.error("! Setup SecurityMode failed.")
      return
    if not await self.ble.setLocalIoCapabilitiesReq(self.iocap):
      syslog.error("! Setup Local IO Capabilities failed.")
      return
    asyncCheck self.advertisingHandler()
    asyncCheck self.eventHandler()
    self.running = true

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBleNim*(debug = false, debug_stack = false, mode: SecurityMode = SecurityMode.Level2,
    iocap: IoCap = IoCap.NoInputNoOutput, initialize = false): BleNim =
  let res = new BleNim
  res.ble = newBleClient(debug, debug_stack)
  res.mode = mode
  res.iocap = iocap
  res.waiter.waitDeviceQueue = newMailbox[BleDevice](16)
  res.waiter.waiting = false
  if initialize:
    if not waitFor res.init():
      return
  result = res

# ==============================================================================
# Scanner
# ==============================================================================

# ------------------------------------------------------------------------------
# API: Start/Stop Scanning
# ------------------------------------------------------------------------------
proc startStopScan*(self: BleNim, active: bool, enable: bool, filterDuplicates = true):
    Future[bool] {.async.} =
  const procName = "startStopScan"
  if enable == self.scan.enable:
    if active != self.scan.active:
      syslog.error(&"! {procName}: Another type of scan is already in progress.")
    else:
      result = true
    return
  if enable:
    let scanType = if active: ScanType.Active else: ScanType.Passive
    if not await self.ble.setScanParametersReq(scanType, ownAddrType = AddrType.Public,
        ownRandomAddrType = RandomAddrType.Static):
      syslog.error(&"! {procName}: setup scan parameters failed.")
      return
    self.devices.clear()
    result = await self.ble.setScanEnableReq(scanEnable = true, filterDuplicates)
    if not result:
      syslog.error(&"! {procName}: enable scannning failed.")
      return
    self.scan.active = active
    self.scan.enable = true
    self.scan.filter = filterDuplicates
  else:
    result = await self.ble.setScanEnableReq(scanEnable = false, self.scan.filter)
    self.scan.enable = false

# ------------------------------------------------------------------------------
# API: Get All devices
# ------------------------------------------------------------------------------
proc allDevices*(self: BleNim): seq[BleDevice] =
  let nums = self.devices.len
  result = newSeqOfCap[BleDevice](nums)
  for device in self.devices.values:
    result.add(device)

# ------------------------------------------------------------------------------
# API: Find device by Name
# ------------------------------------------------------------------------------
proc findDeviceByName*(self: BleNim, name: string): Option[BleDevice] =
  for device in self.devices.values:
    if device.name.isSome and device.name.get == name:
      return some(device)

# ------------------------------------------------------------------------------
# API: Find device by BD Address
# ------------------------------------------------------------------------------
proc findDeviceByAddr*(self: BleNim, bdAddr: string): Option[BleDevice] =
  let address_opt = bdAddr.string2bdAddr()
  if address_opt.isNone:
    return
  let address = address_opt.get()
  for peer, device in self.devices.pairs:
    if peer.address == address:
      result = some(device)
      break

# ------------------------------------------------------------------------------
# API: Wait device
# ------------------------------------------------------------------------------
proc waitDevice*(self: BleNim, devices: seq[string] = @[], timeout = 0):
    Future[Option[BleDevice]] {.async.} =
  proc calcWait(endTime: float): int =
    let nowTs = now().toTime.toUnixFloat
    result = ((endTime - nowTs) * 1000.0 + 0.5).int

  let devicesUpperCase = devices.mapIt(it.toUpper)
  if devicesUpperCase.len > 0:
    for devWaiting in devicesUpperCase:
      let device_opt = self.findDeviceByAddr(devWaiting)
      if device_opt.isSome:
        return device_opt
  if not self.waiter.fut_device.isNil:
    if self.waiter.fut_device.finished:
      discard self.waiter.fut_device.read()
      self.waiter.fut_device = nil
  # not found
  let startTime = now().toTime.toUnixFloat()
  let endTime = startTime + timeout.float / 1000.0
  self.waiter.waiting = true
  defer: self.waiter.waiting = false
  while true:
    var dev_opt: Option[BleDevice]
    if self.waiter.fut_device.isNil:
      self.waiter.fut_device = self.waiter.waitDeviceQueue.get()
    if timeout > 0:
      let waitTime = calcWait(endTime)
      if waitTime > 0:
        let received = await withTimeout(self.waiter.fut_device, waitTime)
        if not received:
          return
        dev_opt = self.waiter.fut_device.read()
      else:
        return
    else:
      dev_opt = await self.waiter.fut_device
    self.waiter.fut_device = nil
    let devNew = dev_opt.get()
    if devices.len == 0 or devNew.bdAddrStr in devicesUpperCase:
      return dev_opt

# ==============================================================================
# Security
# ==============================================================================

# ------------------------------------------------------------------------------
# API: Setup Remote Collection Keys
# ------------------------------------------------------------------------------
proc setRemoteCollectionKeys*(self: BleNim, keys: RemoteCollectionKeys):
    Future[bool] {.async.} =
  result = await self.ble.setRemoteCollectionKeyReq(keys)

proc setRemoteCollectionKeys*(self: BleNim, keysJson: JsonNode): Future[bool] {.async.} =
  try:
    let keys = keysJson.to(RemoteCollectionKeys)
    result = await self.ble.setRemoteCollectionKeyReq(keys)
  except:
    discard

# ------------------------------------------------------------------------------
# API: Setup All Remote Collection Keys
# ------------------------------------------------------------------------------
proc setAllRemoteCollectionKeys*(self: BleNim, allKeys: seq[RemoteCollectionKeys]):
    Future[int] {.async.} =
  for keys in allKeys.items:
    if keys.valid:
      let res = await self.setRemoteCollectionKeys(keys)
      if res:
        result.inc

proc setAllRemoteCollectionKeys*(self: BleNim, allKeysJson: JsonNode): Future[int] {.async.} =
  try:
    let allKeys = allKeysJson.to(seq[RemoteCollectionKeys])
    result = await self.setAllRemoteCollectionKeys(allKeys)
  except:
    discard

# ------------------------------------------------------------------------------
# API: Get Remote Collection Keys (保存用)
# ------------------------------------------------------------------------------
proc getAllRemoteCollectionKeys*(self: BleNim): seq[RemoteCollectionKeys] =
  result = newSeqOfCap[RemoteCollectionKeys](5)
  for device in self.devices.values:
    let keys = device.keys
    if keys.valid:
      result.add(keys)

# ==============================================================================
# GATT
# ==============================================================================

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc connect(self: BleNim, connParams: GattConnParams, timeout: int):
    Future[Option[Gatt]] {.async.} =
  let client_opt = await self.ble.gattConnect(connParams, timeout = timeout)
  if client_opt.isNone:
    discard await self.ble.gattCommonConnectCancelIns()
    return
  let res = new Gatt
  res.gatt = client_opt.get()
  res.peer = connParams.peer
  result = some(res)

# ------------------------------------------------------------------------------
# API: Connection
# ------------------------------------------------------------------------------
proc connect*(self: BleNim, device: BleDevice, timeout = 10 * 1000):
    Future[Option[Gatt]] {.async.} =
  let address = device.bdAddr.address
  let random = (device.bdAddr.addrType == AddrType.Random)
  let connParams = gattDefaultGattConnParams(address, random)
  result = await self.connect(connParams, timeout)

# ------------------------------------------------------------------------------
# API: Connection
# ------------------------------------------------------------------------------
proc connect*(self: BleNim, deviceAddr: string, random = false, timeout = 10 * 1000):
    Future[Option[Gatt]] {.async.} =
  let address_opt = deviceAddr.string2bdAddr()
  if address_opt.isNone:
    return
  let address = address_opt.get()
  let connParams = gattDefaultGattConnParams(address, random)
  result = await self.connect(connParams, timeout)

# ------------------------------------------------------------------------------
# API: Disconnect
# ------------------------------------------------------------------------------
proc disconnect*(self: Gatt) {.async.} =
  discard await self.gatt.disconnect()
  self.gatt = nil

# ------------------------------------------------------------------------------
# API: Read Characteristics
# ------------------------------------------------------------------------------
proc readGattChar*(self: Gatt, handle: uint16): Future[Option[seq[uint8]]] {.async.} =
  result = await self.gatt.gattReadCharacteristicValue(handle)

proc readGattChar*(self: Gatt, uuid: string): Future[Option[seq[HandleValue]]] {.async.} =
  result = await self.gatt.gattReadUsingCharacteristicUuid(0x0001'u16,
      0xffff'u16, uuid)

# ------------------------------------------------------------------------------
# API: Write Characteristics
# ------------------------------------------------------------------------------
proc writeGattChar*(self: Gatt, handle: uint16, value: seq[uint8|char]|string):
    Future[bool] {.async.} =
  result = await self.gatt.gattWriteCharacteristicValue(handle, value)

proc writeGattChar*(self: Gatt, handle: uint16, value: uint16|uint8): Future[bool] {.async.} =
  result = await self.gatt.gattWriteCharacteristicValue(handle, value)

# ------------------------------------------------------------------------------
# API: Read Descriptors
# ------------------------------------------------------------------------------
proc readGattDescriptor*(self: Gatt, handle: uint16): Future[Option[seq[uint8]]] {.async.} =
  result = await self.gatt.gattReadCharacteristicDescriptors(handle)

# ------------------------------------------------------------------------------
# API: Write Descriptors
# ------------------------------------------------------------------------------
proc writeGattDescriptor*(self: Gatt, handle: uint16, desc: uint16): Future[bool] {.async.} =
  result = await self.gatt.gattWriteCharacteristicDescriptors(handle, desc)


when isMainModule:
  import std/os
  const KeysFile = "/tmp/ble_keys.json"

  proc handleDevice(self: BleNim, dev: BleDevice) {.async.} =
    echo "=== Device found."
    echo &"* Address: {dev.bdAddrStr}"
    if dev.name.isSome:
      echo &"* Name: {dev.name.get}"
    echo &"* RSSI: {dev.rssi} [dBm]"
    for retry in 0 ..< 3:
      echo &"* [{retry + 1}] Try to connect..."
      let gatt_opt = await self.connect(dev)
      if gatt_opt.isSome:
        echo "---> connected"
        let gatt = gatt_opt.get()
        echo "wait..."
        await sleepAsync(10 * 1000)
        let value = await gatt.readGattChar(0x0010'u16)
        echo value
        await sleepAsync(5 * 1000)
        if dev.keys.valid:
          echo dev.keys
        let allKeys = self.getAllRemoteCollectionKeys()
        if allKeys.len > 0:
          echo allKeys
          echo %allKeys
          KeysFile.writeFile((%allKeys).pretty)
        echo "done."
        break
      else:
        await sleepAsync(100)

  proc asyncMain() {.async.} =
    let ble = newBleNim(debug = true, mode = SecurityMode.Level2,
        iocap = IoCap.NoInputNoOutput)
    if not await ble.init():
      return
    if fileExists(KeysFile):
      let content = KeysFile.readFile().parseJson()
      let res = await ble.setAllRemoteCollectionKeys(content)
      echo &"*** restore AllKeys -> result: {res}"
    if not await ble.startStopScan(active = false, enable = true):
      echo "failed to start scannning!"
      return
    echo "* wait for scanning..."
    var
      dev: BleDevice
    for retry in 0 ..< 30:
      echo &"[{retry + 1}] waiting..."
      let dev_opt = await ble.waitDevice(devices = @["64:33:DB:86:5D:04"],
        timeout = 1000)
      if dev_opt.isNone:
        continue
      dev = dev_opt.get()
      discard await ble.startStopScan(active = false, enable = false)
      await ble.handleDevice(dev)
      break
    let devices = ble.allDevices()
    echo &"* scanned devices num: {devices.len}"

  waitFor asyncMain()

# old test
#when isMainModule:
when false:
  import nim_nucleus/app
  try:
    waitFor asyncMain()
  except:
    let e = getCurrentException()
    echo e.getStackTrace()
