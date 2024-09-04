import std/asyncdispatch
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
    devices: Table[uint64, BleDevice]
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
    self.devices[report.peer.address] = device
    if self.waiter.waiting and (not self.waiter.waitDeviceQueue.full):
      await self.waiter.waitDeviceQueue.put(device)

# ==============================================================================
# Event
# ==============================================================================

# ------------------------------------------------------------------------------
# Handler: GAP/SM Events
# ------------------------------------------------------------------------------
proc eventHandler(self: BleNim) {.async.} =
  while true:
    let payload = await self.ble.waitEvent()
    let notify_opt = payload.parseEvent()
    if notify_opt.isNone:
      continue

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
proc newBleNim*(debug = false, mode: SecurityMode, iocap: IoCap, initialize = false):
    BleNim =
  new result
  result.ble = newBleClient(debug)
  result.mode = mode
  result.iocap = iocap
  result.waiter.waitDeviceQueue = newMailbox[BleDevice](16)
  result.waiter.waiting = false
  if initialize:
    discard waitFor result.init()

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

# ==============================================================================
# Scanner
# ==============================================================================

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
  let device = self.devices.getOrDefault(address, nil)
  if device != nil:
    result = some(device)

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
    for waitDevice in devicesUpperCase:
      let device_opt = self.findDeviceByAddr(waitDevice)
      if device_opt.isSome:
        return device_opt
  if not self.waiter.fut_device.isNil:
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
# GATT
# ==============================================================================

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `=destroy`(x: GattObj) =
  try:
    discard waitFor x.gatt.disconnect()
  except:
    discard

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
proc connect*(self: BleNim, device: string, random = false, timeout = 10 * 1000):
    Future[Option[Gatt]] {.async.} =
  let address_opt = device.string2bdAddr()
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
# API: Read Descriptors
# ------------------------------------------------------------------------------
proc readGattDescriptor*(self: Gatt, handle: uint16): Future[Option[seq[uint8]]] {.async.} =
  result = await self.gatt.gattReadCharacteristicDescriptors(handle)



when isMainModule:
  proc asyncMain() {.async.} =
    let ble = newBleNim(mode = SecurityMode.Level2, iocap = IoCap.NoInputNoOutput)
    if not await ble.init():
      return
    if not await ble.startStopScan(active = false, enable = true):
      echo "failed to start scannning!"
      return
    echo "* wait for scanning..."
    while true:
      let dev_opt = await ble.waitDevice(devices = @["cc:c1:aa:20:0d:61"],
        timeout = 10000)
      if dev_opt.isNone:
        break
      let dev = dev_opt.get()
      echo "=== Device found."
      echo &"* Address: {dev.bdAddrStr}"
      if dev.name.isSome:
        echo &"* Name: {dev.name.get}"
      echo &"* RSSI: {dev.rssi} [dBm]"
      break
    discard await ble.startStopScan(active = false, enable = false)
    let devices = ble.allDevices()
    echo &"* scanned devices num: {devices.len}"

  waitFor asyncMain()

# old test
when false:
  import app
  try:
    waitFor asyncMain()
  except:
    let e = getCurrentException()
    echo e.getStackTrace()
