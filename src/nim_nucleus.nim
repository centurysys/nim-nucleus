import std/asyncdispatch
import std/enumutils
import std/json
import std/options
import std/sequtils
import std/strformat
import std/strutils
import std/tables
import std/times
import results
import nim_nucleus/submodule
export results, asyncsync
export SecurityMode, IoCap, PeerAddr
export HandleValue, ErrorCode
export util

type
  ScanState = object
    active: bool
    enable: bool
    filter: bool
  BleDeviceObj* = object
    peer*: PeerAddr
    peerAddrStr*: string
    name*: Option[string]
    rssi*: int8
    seenTime*: Time
    keys: RemoteCollectionKeys
  BleDevice* = ref BleDeviceObj
  DeviceWait = object
    waitDeviceQueue: Mailbox[BleDevice]
    fut_device: Future[Result[BleDevice, ErrorCode]]
    waiting: bool
  BleNimObj = object
    ble: BleClient
    mode: SecurityMode
    iocap: IoCap
    running: bool
    scan: ScanState
    eventQueue: AsyncQueue[string]
    devices: Table[PeerAddr, BleDevice]
    bondedKeys: Table[PeerAddr, RemoteCollectionKeys]
    tblGatt: Table[PeerAddr, Gatt]
    waiter: DeviceWait
  BleNim* = ref BleNimObj
  GattObj = object
    ble: BleNim
    gatt: GattClient
    peer: PeerAddr
    connected: bool
  Gatt* = ref GattObj

# ==============================================================================
# Utility
# ==============================================================================

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `$`*(x: BleDevice): string =
  var buf = newSeqOfCap[string](16)
  buf.add("--- BleDevice Informations ---")
  buf.add(&"* Peer: {x.peer}")
  if x.name.isSome:
    buf.add(&"* Name: {x.name.get}")
  buf.add(&"* RSSI: {x.rssi} [dBm]")
  if x.keys.valid:
    buf.add("  -- Remote Collection Keys --")
    buf.add($(x.keys))
  result = buf.join("\n")

# ==============================================================================
# Advertising
# ==============================================================================

# ------------------------------------------------------------------------------
# Handler: Advertising
# ------------------------------------------------------------------------------
proc advertisingHandler(self: BleNim) {.async.} =
  while true:
    let payload_res = await self.ble.waitAdvertising()
    if payload_res.isErr:
      break
    let payload = payload_res.get()
    let report_opt = payload.parseAdvertisingReport()
    if report_opt.isNone:
      continue
    let report = report_opt.get()
    let device = new BleDevice
    device.peer = report.peer
    device.peerAddrStr = bdAddr2string(report.peer.address)
    device.name = report.name
    device.rssi = report.rssi
    device.seenTime = now().toTime
    self.devices[report.peer] = device
    if self.waiter.waiting and (not self.waiter.waitDeviceQueue.full):
      discard await self.waiter.waitDeviceQueue.put(device)

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
    device.keys.peerAddrStr = peer.address.bdAddr2string()
    self.bondedKeys[peer] = device.keys

# ------------------------------------------------------------------------------
# GAP: LE Encryption Change 通知
# ------------------------------------------------------------------------------
proc handleEncryptionChange(self: BleNim, event: EncryptionChangeEvent) {.async.} =
  let conHandle = event.conHandle
  let enable = event.encryptionEnabled
  discard await self.ble.handleEncryptionChange(conHandle, enable)

# ------------------------------------------------------------------------------
# GAP: LE Disconnection Complete 通知
# ------------------------------------------------------------------------------
proc handleDisconnectionComplete(self: BleNim, event: DisconnectionCompleteEvent)
    {.async.} =
  let conHandle = event.conHandle
  let peer_opt = await self.ble.handleDisconnectionComplete(conHandle)
  if peer_opt.isSome:
    let peer = peer_opt.get()
    let gatt = self.tblGatt.getOrDefault(peer)
    if not gatt.isNil:
      gatt.connected = false

# ------------------------------------------------------------------------------
# Handler: GAP/SM Events
# ------------------------------------------------------------------------------
proc eventHandler(self: BleNim) {.async.} =
  while true:
    let payload_res = await self.ble.waitEvent()
    if payload_res.isErr:
      continue
    let payload = payload_res.get()
    let notify_opt = payload.parseEvent()
    if notify_opt.isNone:
      continue
    let notify = notify_opt.get()
    case notify.event
    of SmLocalSecurityProperty:
      # LE ローカルセキュリティ設定通知
      let data = notify.localSecurityData
      self.setLocalSecurityData(data)
    of SmLtkReceive:
      # LE LTK 受信通知
      let data = notify.peerLtkData
      self.setLtk(data)
    of SmEdivRandReceive:
      # LE EDIV Rand 受信通知
      let data = notify.peerEdivRandData
      self.setEdivRand(data)
    of SmIrkReceive:
      # LE IRK 受信通知
      let data = notify.peerIrkData
      self.setIrk(data)
    of SmCsrkReceive:
      # LE CSRK 受信通知
      let data = notify.peerCsrkData
      self.setCsrk(data)
    of SmAuthenticationComplete:
      # LE 認証完了通知
      let data = notify.authCompleteData
      self.setAuthCompleted(data)
    of GapEncryptionChange:
      # LE Encryption Change 通知
      let data = notify.leEncryptionChangeData
      await self.handleEncryptionChange(data)
    of GapDisconnectionComplete:
      # LE Disconnection Complete 通知
      let data = notify.leDisconData
      await self.handleDisconnectionComplete(data)
    else:
      let eventName = notify.event.symbolName
      let logmsg = &"* eventHandler: unhandled event: {eventName}"
      syslog.info(logmsg)

# ------------------------------------------------------------------------------
# API: async initialization
# ------------------------------------------------------------------------------
proc init*(self: BleNim): Future[bool] {.async.} =
  ## BleNim 内部で使用している NetNucleus の初期化を行う。
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
  ## BleNim インスタンスの初期化
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
  ## Scan の有効・無効を設定する。
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
  ## アドバタイジング情報を受信したペリフェラル情報の一覧を取得する
  let nums = self.devices.len
  result = newSeqOfCap[BleDevice](nums)
  for device in self.devices.values:
    result.add(device)

# ------------------------------------------------------------------------------
# API: Find device by Name
# ------------------------------------------------------------------------------
proc findDeviceByName*(self: BleNim, name: string): Option[BleDevice] =
  ## アドバタイジング情報を受信したペリフェラルを名前で検索する
  for device in self.devices.values:
    if device.name.isSome and device.name.get == name:
      return some(device)

# ------------------------------------------------------------------------------
# API: Find device by BD Address
# ------------------------------------------------------------------------------
proc findDeviceByAddr*(self: BleNim, peer: string): Option[BleDevice] =
  ## アドバタイジング情報を受信したペリフェラルを Bluetooth アドレスで検索する。
  ##
  ## アドレスの形式は "aa:bb:cc:dd:ee:ff" とする。
  let address_opt = peer.string2bdAddr()
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
    Future[Result[BleDevice, ErrorCode]] {.async.} =
  ## 指定したデバイスのアドバタイジングを受信するまで待機する。
  proc calcWait(endTime: float): int =
    let nowTs = now().toTime.toUnixFloat
    result = ((endTime - nowTs) * 1000.0 + 0.5).int

  let devicesUpperCase = devices.mapIt(it.toUpper)
  if devicesUpperCase.len > 0:
    for devWaiting in devicesUpperCase:
      let device_opt = self.findDeviceByAddr(devWaiting)
      if device_opt.isSome:
        return ok(device_opt.get())
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
    var dev_res: Result[BleDevice, ErrorCode]
    if self.waiter.fut_device.isNil:
      self.waiter.fut_device = self.waiter.waitDeviceQueue.get()
    if timeout > 0:
      let waitTime = calcWait(endTime)
      if waitTime > 0:
        let received = await withTimeout(self.waiter.fut_device, waitTime)
        if not received:
          return err(ErrorCode.Timeouted)
        dev_res = self.waiter.fut_device.read()
      else:
        return err(ErrorCode.ValueError)
    else:
      dev_res = await self.waiter.fut_device
    self.waiter.fut_device = nil
    let devNew = dev_res.get()
    if devices.len == 0 or devNew.peerAddrStr in devicesUpperCase:
      return ok(dev_res.get)

# ==============================================================================
# Security
# ==============================================================================

# ------------------------------------------------------------------------------
# API: Setup Remote Collection Keys
# ------------------------------------------------------------------------------
proc setRemoteCollectionKeys*(self: BleNim, keys: RemoteCollectionKeys):
    Future[bool] {.async.} =
  ## Central として動作する際の Peripheral の各種暗号化鍵を登録する。
  result = await self.ble.setRemoteCollectionKeyReq(keys)
  if result:
    let peer = keys.peer
    self.bondedKeys[peer] = keys

proc setRemoteCollectionKeys*(self: BleNim, keysJson: JsonNode): Future[bool] {.async.} =
  ## 上の関数と機能は同じだが、RemoteCollectionKeys を JSON 化した JsonNode 形式を引数にする。
  try:
    let keys = keysJson.to(RemoteCollectionKeys)
    result = await self.setRemoteCollectionKeys(keys)
  except:
    discard

# ------------------------------------------------------------------------------
# API: Setup All Remote Collection Keys
# ------------------------------------------------------------------------------
proc setAllRemoteCollectionKeys*(self: BleNim, allKeys: seq[RemoteCollectionKeys]):
    Future[int] {.async.} =
  ## Central として動作する際の 全 Peripheral の各種暗号化鍵を一括登録する。
  for keys in allKeys.items:
    if keys.valid:
      let res = await self.setRemoteCollectionKeys(keys)
      if res:
        result.inc

proc setAllRemoteCollectionKeys*(self: BleNim, allKeysJson: JsonNode): Future[int] {.async.} =
  ## 上の関数と機能は同じだが、seq\[RemoteCollectionKeys\] を JSON 化した JsonNode 形式を引数にする。
  try:
    let allKeys = allKeysJson.to(seq[RemoteCollectionKeys])
    result = await self.setAllRemoteCollectionKeys(allKeys)
  except:
    discard

# ------------------------------------------------------------------------------
# API: Get Remote Collection Keys (保存用)
# ------------------------------------------------------------------------------
proc getAllRemoteCollectionKeys*(self: BleNim): seq[RemoteCollectionKeys] =
  ## ペアリング済みデバイスの情報を一括で取得する。
  ##
  ## 次回起動時にペアリング情報を復旧させるためにはこれを保存しておく必要がある。
  result = newSeqOfCap[RemoteCollectionKeys](5)
  for keys in self.bondedKeys.values:
    if keys.valid:
      result.add(keys)

# ------------------------------------------------------------------------------
# API: Remove Remote Collection Keys
# ------------------------------------------------------------------------------
proc removeRemoteCollectionKeys*(self: BleNim, peer: PeerAddr): Future[bool] {.async.} =
  ## ペアリング済みデバイスの情報を削除する。
  let keys = self.bondedKeys.getOrDefault(peer)
  if not keys.valid:
    return
  let peer = keys.peer
  let res = await self.ble.deleteRemoteDeviceKeyReq(peer)
  if not res:
    return
  let device = self.devices.getOrDefault(peer)
  if not device.isNil:
    zeroMem(addr device.keys, device.keys.sizeof)
  result = true

# ==============================================================================
# GATT
# ==============================================================================

type
  CharaUuid* {.pure.} = enum
    DeviceName = "2a00"
    Appearance = "2a01"
    DateTime = "2a08"
    BatteryLevel = "2a19"
    ModelNumber = "2a24"
    SerialNumber = "2a25"
    FirmwareRevision = "2a26"
    HardwareRevision = "2a27"
    SoftwareRevision = "2a28"
    ManufactureName = "2a29"
    SystemId = "2a23"
    RegCert = "2a2a"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc connect(self: BleNim, connParams: GattConnParams, timeout: int):
    Future[Result[Gatt, ErrorCode]] {.async.} =
  let client_res = await self.ble.gattConnect(connParams, timeout = timeout)
  if client_res.isErr:
    discard await self.ble.gattCommonConnectCancelIns()
    return err(client_res.error)
  let res = new Gatt
  res.gatt = client_res.get()
  res.peer = connParams.peer
  res.connected = true
  res.ble = self
  self.tblGatt[res.peer] = res
  result = ok(res)

# ------------------------------------------------------------------------------
# API: Connection
# ------------------------------------------------------------------------------
proc connect*(self: BleNim, device: BleDevice, timeout = 10 * 1000):
    Future[Result[Gatt, ErrorCode]] {.async.} =
  ## ペリフェラルに GATT 接続を行う。
  let address = device.peer.address
  let random = (device.peer.addrType == AddrType.Random)
  let connParams = gattDefaultGattConnParams(address, random)
  result = await self.connect(connParams, timeout)

# ------------------------------------------------------------------------------
# API: Connection
# ------------------------------------------------------------------------------
proc connect*(self: BleNim, deviceAddr: string, random = false, timeout = 10 * 1000):
    Future[Result[Gatt, ErrorCode]] {.async.} =
  ## ペリフェラルに GATT 接続を行う。
  let address_opt = deviceAddr.string2bdAddr()
  if address_opt.isNone:
    return err(ErrorCode.ValueError)
  let address = address_opt.get()
  let connParams = gattDefaultGattConnParams(address, random)
  result = await self.connect(connParams, timeout)

# ------------------------------------------------------------------------------
# API: Disconnect
# ------------------------------------------------------------------------------
proc disconnect*(self: Gatt, unpair = false) {.async.} =
  ## 接続されている GATT 接続の切断を行う。
  discard await self.gatt.disconnect()
  if unpair:
    discard await self.ble.removeRemoteCollectionKeys(self.peer)
  let peer = self.peer
  if self.ble.tblGatt.hasKey(peer):
    self.ble.tblGatt.del(peer)
  self.gatt = nil

# ------------------------------------------------------------------------------
# API: Wait Encryption Complete
# ------------------------------------------------------------------------------
proc waitEncryptionComplete*(self: Gatt): Future[Result[bool, ErrorCode]] {.async.} =
  ## GATT 接続後即ペアリング要求を送ってくるペリフェラルとの間での
  ## ペアリング処理が完了するまで待機する。
  result = await self.gatt.waitEncryptionComplete()

# ------------------------------------------------------------------------------
# API: Discover Characteristics by UUID
# ------------------------------------------------------------------------------
proc discoverCharacteristicsByUuid*(self: Gatt, uuid: Uuid):
    Future[Result[GattCharacteristicsOfService, ErrorCode]] {.async.} =
  const
    startHandle = 0x0001'u16
    endHandle = 0xffff'u16
  result = await self.gatt.gattDiscoverCharacteristicsByUuid(startHandle, endHandle, uuid)

# ------------------------------------------------------------------------------
# API: Read Characteristics (handle)
# ------------------------------------------------------------------------------
proc readGattChar*(self: Gatt, handle: uint16): Future[Result[seq[uint8], ErrorCode]]
    {.async.} =
  ## キャラクタリスティック値を読み取る (ハンドル指定)
  result = await self.gatt.gattReadCharacteristicValue(handle)

# ------------------------------------------------------------------------------
# API: Read Characteristics (UUID string)
# ------------------------------------------------------------------------------
proc readGattChar*(self: Gatt, uuid: string): Future[Result[HandleValue, ErrorCode]]
    {.async.} =
  ## キャラクタリスティック値を読み取る (UUID 指定)
  let handleValues_res = await self.gatt.gattReadUsingCharacteristicUuid(0x0001'u16,
      0xffff'u16, uuid)
  if handleValues_res.isOk:
    let handleValues = handleValues_res.get()
    result = ok(handleValues[0])
  else:
    result = err(handleValues_res.error)

# ------------------------------------------------------------------------------
# API: Read Characteristics (UUID enum)
# ------------------------------------------------------------------------------
proc readGattChar*(self: Gatt, uuid: CharaUuid): Future[Result[HandleValue, ErrorCode]]
    {.async.} =
  let handleValues_res = await self.gatt.gattReadUsingCharacteristicUuid(0x0001'u16,
      0xffff'u16, $uuid)
  if handleValues_res.isOk:
    let handleValues = handleValues_res.get()
    result = ok(handleValues[0])
  else:
    result = err(handleValues_res.error)

# ------------------------------------------------------------------------------
# API: Write Characteristics
# ------------------------------------------------------------------------------
proc writeGattChar*(self: Gatt, handle: uint16, value: seq[uint8|char]|string):
    Future[Result[bool, ErrorCode]] {.async.} =
  ## キャラクタリスティック値を書き込む (ハンドル指定)
  result = await self.gatt.gattWriteCharacteristicValue(handle, value)

proc writeGattChar*(self: Gatt, handle: uint16, value: uint16|uint8):
    Future[Result[bool, ErrorCode]] {.async.} =
  result = await self.gatt.gattWriteCharacteristicValue(handle, value)

# ------------------------------------------------------------------------------
# API: Read Descriptors
# ------------------------------------------------------------------------------
proc readGattDescriptor*(self: Gatt, handle: uint16): Future[Result[seq[uint8], ErrorCode]]
    {.async.} =
  ## ディスクリプタ値を読み取る (ハンドル指定)
  result = await self.gatt.gattReadCharacteristicDescriptors(handle)

# ------------------------------------------------------------------------------
# API: Write Descriptors
# ------------------------------------------------------------------------------
proc writeGattDescriptor*(self: Gatt, handle: uint16, desc: uint16):
    Future[Result[bool, ErrorCode]] {.async.} =
  result = await self.gatt.gattWriteCharacteristicDescriptors(handle, desc)

# ------------------------------------------------------------------------------
# API: Wait Notification
# ------------------------------------------------------------------------------
proc waitNotification*(self: Gatt, timeout = 0): Future[Result[HandleValue, ErrorCode]]
    {.async.} =
  ## Notification/Indication を受信する。
  let res = await self.gatt.waitNotify(timeout)
  if res.isErr:
    return res.error.err
  var handleValue: HandleValue
  handleValue.handle = res.get.handle
  handleValue.value = res.get.values.items.toSeq.mapIt(it.uint8)
  result = handleValue.ok


when isMainModule:
  import std/os
  const KeysFile = "/tmp/ble_keys.json"

  proc notificationHandler(self: Gatt) {.async.} =
    while self.connected:
      let val_res = await self.waitNotification(1000)
      if val_res.isErr:
        if val_res.error == ErrorCode.Disconnected:
          echo "** notificationHandler: Disconnected."
          break
        else:
          continue
      let val = val_res.get()
      let values = val.value.mapIt(&"{it:02x}").join(", ")
      echo &"** Notify: handle: 0x{val.handle:04x}, values: [{values}]"

  proc readBufferSize(self: Gatt): Future[Result[bool, ErrorCode]] {.async.} =
    const handle = 0x002e'u16
    let cmd = @[0x02'u8, 0x00'u8, 0xd6'u8]
    let res_res = await self.writeGattChar(handle, cmd)
    if res_res.isErr:
      if res_res.error == ErrorCode.Disconnected:
        echo "** readBufferSize: Disconnected."
      return err(res_res.error)
    let res = res_res.get()
    if not res:
      echo "??? write custom characteristic failed."
      return
    let buf_res = await self.readGattChar(handle)
    if buf_res.isOk:
      let buf = buf_res.get()
      result = ok(buf[3] == 0x01'u8)

  proc setBufferEnable(self: Gatt, enable: bool): Future[Result[bool, ErrorCode]]
      {.async.} =
    const handle = 0x002e'u16
    let param = if enable: 0x01'u8 else: 0x00'u8
    let cmd = @[0x03'u8, 0x01'u8, 0xa6'u8, param]
    result = await self.writeGattChar(handle, cmd)
    if result.isErr:
      if result.error == ErrorCode.Disconnected:
        echo "** setBufferEnable: Disconnected."
      return err(result.error)
    if not result.get:
      echo "??? write custom characteristic failed."

  proc setDateTime(self: Gatt): Future[Result[bool, ErrorCode]] {.async.} =
    const handle = 0x002e'u16
    let now = now()
    let year = (now.year - 2000).uint8
    let cmd = @[0x08'u8, 0x01'u8, 0x01'u8,
        year, now.month.uint8, now.monthday.uint8,
        now.hour.uint8, now.minute.uint8, now.second.uint8]
    result = await self.writeGattChar(handle, cmd)
    if result.isErr:
      if result.error == ErrorCode.Disconnected:
        echo "** setDateTime: Disconnected."
      return err(result.error)
    echo &" setDateTime -> result: {result.get}"

  proc handleGatt(self: Gatt) {.async.} =
    asyncCheck self.notificationHandler()
    echo "*** Wait for Encryption complete..."
    let enc_res = await self.waitEncryptionComplete()
    if enc_res.isOk:
      echo " --> Encryption completed."
    else:
      echo "!!! Disconnected ??"
      return
    const items = [CharaUuid.DeviceName, CharaUuid.ModelNumber,
        CharaUuid.HardwareRevision, CharaUuid.FirmwareRevision,
        CharaUuid.SoftwareRevision, CharaUuid.ManufactureName]
    for item in items:
      let handleValue_res = await self.readGattChar(item)
      if handleValue_res.isErr:
        let err = handleValue_res.error
        if err == ErrorCode.Disconnected:
          echo "!! handleGatt: device disconnected."
          await self.disconnect(unpair = false)
          return
      else:
        let handleValue = handleValue_res.get()
        echo &"* {item.symbolName} --> 0x{handleValue.handle:04x}:" &
            &" {handleValue.value.toString}"
    await sleepAsync(1000)
    let bufEnabled_res = await self.readBufferSize()
    if bufEnabled_res.isErr:
      let err = bufEnabled_res.error
      if err == ErrorCode.Disconnected:
        echo "!! handleGatt: device disconnected."
        await self.disconnect(unpair = false)
        return
    else:
      let bufEnabled = bufEnabled_res.get()
      echo &"buffer enable: {bufEnabled}"
      if not bufEnabled:
        discard await self.setBufferEnable(true)
      discard await self.setDateTime()
    echo "wait..."
    await sleepAsync(2 * 1000)
    let res = await self.writeGattDescriptor(0x0013'u16, 0x0002'u16)
    echo &"write CCC(Desc) -> {res}"
    while self.connected:
      await sleepAsync(1000)
    await self.disconnect(unpair = false)

  proc handleDevice(self: BleNim, dev: BleDevice) {.async.} =
    echo "=== Device found."
    echo &"* Address: {dev.peerAddrStr}"
    if dev.name.isSome:
      echo &"* Name: {dev.name.get}"
    echo &"* RSSI: {dev.rssi} [dBm]"
    for retry in 0 ..< 3:
      echo &"* [{retry + 1}] Try to connect..."
      let gatt_res = await self.connect(dev)
      if gatt_res.isOk:
        echo "---> connected"
        let gatt = gatt_res.get()
        await gatt.handleGatt()
        break
      else:
        await sleepAsync(100)
    if dev.keys.valid:
      echo dev.keys
    let allKeys = self.getAllRemoteCollectionKeys()
    if allKeys.len > 0:
      for allKey in allKeys:
        echo allKey
      KeysFile.writeFile($(%allKeys))
    elif KeysFile.fileExists:
      KeysFile.removeFile()
    echo "done."

  proc asyncMain() {.async.} =
    let ble = newBleNim(debug = true, debug_stack = false,
        mode = SecurityMode.Level2, iocap = IoCap.NoInputNoOutput)
    if not await ble.init():
      return
    if fileExists(KeysFile):
      let content = KeysFile.readFile().parseJson()
      let res = await ble.setAllRemoteCollectionKeys(content)
      echo &"*** restore AllKeys -> result: {res}"
    if not await ble.startStopScan(active = true, enable = true):
      echo "failed to start scannning!"
      return
    echo "* wait for scanning..."
    for retry in countDown(10, 0):
      echo &"[{retry}] waiting..."
      await sleepAsync(1000)
    var
      dev: BleDevice
      scanStopped = false
    for retry in 0 ..< 30:
      echo &"[{retry + 1}] waiting..."
      let dev_res = await ble.waitDevice(devices = @["64:33:DB:86:5D:04"],
        timeout = 1000)
      if dev_res.isErr:
        continue
      dev = dev_res.get()
      discard await ble.startStopScan(active = true, enable = false)
      scanStopped = true
      await ble.handleDevice(dev)
      break
    let devices = ble.allDevices()
    echo &"* scanned devices num: {devices.len}"
    for device in devices:
      echo device
    if not scanStopped:
      discard await ble.startStopScan(active = true, enable = false)

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
