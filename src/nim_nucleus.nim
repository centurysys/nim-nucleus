import std/asyncdispatch
import std/enumutils
import std/json
import std/options
import std/sequtils
import std/sets
import std/strformat
import std/strutils
import std/tables
import std/times
import results
import nim_nucleuspkg/submodule
export results, asyncsync, mailbox
export SecurityMode, IoCap, PeerAddr, ScanFilterPolicy
export HandleValue, ErrorCode
export util

type
  ScanState = object
    active: bool
    enable: bool
    filter: bool
    interval: uint16
    window: uint16
    filterPolicy: ScanFilterPolicy
    whiteList: HashSet[PeerAddr]
  BleDeviceObj* = object
    peer*: PeerAddr
    peerAddrStr*: string
    name*: Option[string]
    rssi*: int8
    advertiseData*: string
    manufacturerData*: Option[string]
    seenTime*: Time
    keys: RemoteCollectionKeys
  BleDevice* = ref BleDeviceObj
  DeviceWait = object
    waitDeviceQueue: Mailbox[BleDevice]
    fut_device: Future[Result[BleDevice, ErrorCode]]
    waiting: bool
  BleNimObj = object
    ble: BleClient
    path: string
    port: Option[Port]
    mode: SecurityMode
    iocap: IoCap
    running: bool
    scan: ScanState
    scanLock: AsyncLock
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

type
  CCC* {.pure, size: sizeof(uint16).} = enum
    Disable = 0x0000
    Notify = 0x0001
    Indicate = 0x0002

const
  ModName = "BleNim"

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
    device.advertiseData = report.rawdata
    device.manufacturerData = report.manufacturerData
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
# GATT: 切断通知
# ------------------------------------------------------------------------------
proc handleGattDisconnection(self: BleNim, event: GattDisconEvent)
    {.async.} =
  let gattId = event.common.gattId
  let peer_opt = await self.ble.handleGattDisconnection(gattId)
  if peer_opt.isSome:
    let peer = peer_opt.get()
    let gatt = self.tblGatt.getOrDefault(peer)
    if not gatt.isNil:
      discard await gatt.gatt.disconnect()
      gatt.connected = false

# ------------------------------------------------------------------------------
# GAP: LE Connection Complete 通知 (中断時)
# ------------------------------------------------------------------------------
proc handleConnectionComplete(self: BleNim, event: ConnectionCompleteEvent)
    {.async.} =
  discard

# ------------------------------------------------------------------------------
# GATT: 接続通知 (中断時)
# ------------------------------------------------------------------------------
proc handleGattConnection(self: BleNim, event: GattConEvent) {.async.} =
  const ProcName = "handleGattConnection"
  let gattResult = event.common.gattResult
  let gattId = event.common.gattId
  if gattResult == 0:
    syslog.warning(&"* {ProcName}: gattId: {gattId} -> disconnect...")
    let res = await self.ble.gattCommonDisconnectIns(gattId)
    if res.isErr:
      syslog.error(&"! {ProcName}: disconnect failed.")
    else:
      syslog.info(&"* {ProcName}: GATT disconnected.")
  else:
    logGattResult(ProcName, gattResult, detail = true)

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
    of GapReadRemoteUsedFeatures:
      # LE Read Remote Used Features 通知
      discard
    of GapDisconnectionComplete:
      # LE Disconnection Complete 通知
      let data = notify.leDisconData
      await self.handleDisconnectionComplete(data)
    of GattCmnDisconnect:
      # GATT 切断通知 (0x40BB)
      let data = notify.gattDisconData
      await self.handleGattDisconnection(data)
    of SmLtkSend, SmEdivRandSend, SmIrkSend, SmAddressInformationReceive,
        SmAddressInformationSend, SmCsrkSend:
      discard
    of GapConnectionComplete:
      # LE Connection Complete 通知 (GATT接続中断時)
      let data = notify.leConData
      await self.handleConnectionComplete(data)
    of GattCmnConnect:
      # GATT 接続通知 (GATT接続中断時)
      let data = notify.gattConData
      await self.handleGattConnection(data)
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
  if self.port.isSome:
    result = await self.ble.initBTM(self.port.get)
  else:
    result = await self.ble.initBTM(self.path)
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
proc newBleNim*(path: string = socketPath, port: uint16 = 0, debug = false,
    debug_stack = false, mode: SecurityMode = SecurityMode.Level2,
    iocap: IoCap = IoCap.NoInputNoOutput, initialize = false): BleNim =
  ## BleNim インスタンスの初期化
  ## - path: btmd が listen している Unix Domain Socket PATH
  ## - port: localhost の TCP 経由で通信する場合の btmd の listen port(0 以外の場合)
  ## - mode: LE Sucurity Mode
  ##   - SecurityMode.NoAuth: (No authentication and no encryption)
  ##   - SecurityMode.Level2: (LE Security Mode 1 Level 2)
  ##   - SecurityMode.Level4: (LE Security Mode 1 Level 4)
  ## - iocap: ローカルデバイスの IO Capabilities
  ##   - IoCap.DisplayOnly
  ##   - IoCap.DisplayYesNo
  ##   - IoCap.KeyboardOnly
  ##   - IoCap.NoInputNoOutput: MA-S120/LB では実質的にこれのみ
  ##   - IoCap.KeyboardDisplay
  ## - initialize: 初期化処理(BleNim::init() も一緒に実行するかどうか)
  let res = new BleNim
  res.ble = newBleClient(debug, debug_stack)
  res.path = path
  if port > 0:
    res.port = some(port.Port)
  res.mode = mode
  res.iocap = iocap
  res.waiter.waitDeviceQueue = newMailbox[BleDevice](16)
  res.waiter.waiting = false
  res.scanLock = newAsyncLock()
  res.scan.whiteList = initHashSet[PeerAddr]()
  if initialize:
    if not waitFor res.init():
      return
  result = res

# ==============================================================================
# GAP (Scanner)
# ==============================================================================

# ------------------------------------------------------------------------------
# API: Get White List Size
# ------------------------------------------------------------------------------
proc getWhiteListSize*(self: BleNim): Future[int] {.async.} =
  result = await self.ble.readWhiteListSizeReq()

# ------------------------------------------------------------------------------
# API: Clear White List
# ------------------------------------------------------------------------------
proc clearWhiteList*(self: BleNim): Future[bool] {.async.} =
  result = await self.ble.clearWhiteListReq()
  if result:
    self.scan.whiteList.clear()

# ------------------------------------------------------------------------------
# API: Add Device to White List
# ------------------------------------------------------------------------------
proc addDeviceToWhiteList*(self: BleNim, deviceAddr: string): Future[bool] {.async.} =
  let peer_opt = deviceAddr.toBdAddr()
  if peer_opt.isNone:
    return
  let peer = peer_opt.get()
  if self.scan.whiteList.contains(peer):
    return true
  result = await self.ble.addDeviceToWhiteListReq(peer)
  if result:
    self.scan.whiteList.incl(peer)

# ------------------------------------------------------------------------------
# API: Remove Device from White List
# ------------------------------------------------------------------------------
proc removeDeviceFromWhiteList*(self: BleNim, deviceAddr: string): Future[bool] {.async.} =
  let peer_opt = deviceAddr.toBdAddr()
  if peer_opt.isNone:
    return
  let peer = peer_opt.get()
  if not self.scan.whiteList.contains(peer):
    return true
  result = await self.ble.removeDeviceFromWhiteListReq(peer)
  if result:
    self.scan.whiteList.excl(peer)

# ------------------------------------------------------------------------------
# API: Get Device in White List
# ------------------------------------------------------------------------------
iterator devicesInWhiteList*(self: BleNim): PeerAddr =
  for device in self.scan.whiteList.items:
    yield device

# ------------------------------------------------------------------------------
# API: Start/Stop Scanning
# ------------------------------------------------------------------------------
proc startStopScan*(self: BleNim, active: bool, enable: bool, scanInterval: uint16 = 0,
    scanWindow: uint16 = 0, filterDuplicates = true,
    filterPolicy = ScanFilterPolicy.AcceptAllExceptDirected): Future[bool] {.async.} =
  ## Scan の有効・無効を設定する。
  ## scanInterval, scanWindow 両方が 0 の場合、以前設定された値を変更しない。
  ## - active: Active Scan/Passive Scan
  ## - enable: Scan 有効/無効
  ## - scanInterval: Scan 間隔: 0x0004〜0x4000, 0.625ms単位、2.5ms〜10240ms
  ## - scanWindow: 1回の Scan あたりの継続時間: 0x0004〜0x4000, 0.625ms単位、2.5ms〜10240ms
  ## - filterDuplicates: Duplicate filtering 有効/無効 切り替え
  ## - filterPolicy: Advertising Packet を受け付ける際のポリシー設定
  ##   - ScanFilterPolicy.AcceptAllExceptDirected
  ##   - ScanFilterPolicy.WhitelistOnly
  ##   - ScanFilterPolicy.AcceptAllExceptNotDirected
  ##   - ScanFilterPolicy.AcceptAllExceptWhitelistAndNotDirected
  const
    procName = "startStopScan"
    defaultInterval: uint16 = 0x00a0
    defaultWindow: uint16 = 0x0030
  if enable == self.scan.enable:
    if active != self.scan.active:
      syslog.error(&"! {procName}: Another type of scan is already in progress.")
    else:
      result = true
    return
  if enable:
    var needSetup = true
    if scanInterval == 0 and scanWindow == 0:
      if self.scan.interval > 0 and self.scan.window > 0 and
          filterPolicy == self.scan.filterPolicy:
        # 以前設定された値を変更しない
        needSetup = false
    if needSetup:
      let paramScanInterval = if scanInterval > 0: scanInterval
          elif self.scan.interval > 0: self.scan.interval
          else: defaultInterval
      let paramScanWindow = if scanWindow > 0: scanWindow
          elif self.scan.window > 0: self.scan.window
          else: defaultWindow
      let scanType = if active: ScanType.Active else: ScanType.Passive
      if not await self.ble.setScanParametersReq(scanType, paramScanInterval,
          paramScanWindow, ownAddrType = AddrType.Public,
          ownRandomAddrType = RandomAddrType.Static,
          filterPolicy = filterPolicy):
        syslog.error(&"! {procName}: setup scan parameters failed.")
        return
      self.scan.interval = paramScanInterval
      self.scan.window = paramScanWindow
      self.scan.active = active
      self.scan.filterPolicy = filterPolicy
    self.devices.clear()
    result = await self.ble.setScanEnableReq(scanEnable = true, filterDuplicates)
    if not result:
      syslog.error(&"! {procName}: enable scannning failed.")
      return
    self.scan.enable = true
    self.scan.filter = filterDuplicates
  else:
    result = await self.ble.setScanEnableReq(scanEnable = false, self.scan.filter)
    self.scan.enable = false

# ------------------------------------------------------------------------------
# API: Restart Scanning
# ------------------------------------------------------------------------------
proc restartScan*(self: BleNim): Future[bool] {.async.} =
  const procName = "restartScan"
  await self.scanLock.acquire()
  defer: self.scanLock.release()
  if self.scan.enable:
    if not await self.startStopScan(active = self.scan.active, enable = false,
        filterDuplicates = self.scan.filter, filterPolicy = self.scan.filterPolicy):
      let errmsg = &"! {procName}: failed to stop scanning."
      syslog.error(errmsg)
      return
    await sleepAsync(50)
  result = await self.startStopScan(active = self.scan.active, enable = true,
      filterDuplicates = self.scan.filter, filterPolicy = self.scan.filterPolicy)
  if not result:
    let errmsg = &"! {procName}: failed to re-start scanning."
    syslog.error(errmsg)

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
proc waitDevice*(self: BleNim, devices: seq[string] = @[], timeout: int = 0):
    Future[Result[BleDevice, ErrorCode]] {.async.} =
  ## 指定したデバイスのアドバタイジングを受信するまで待機する。
  ## - devices: 対象デバイス指定、空の場合はデバイスを限定しない
  ## - timeout: ms 単位で指定。0 の場合はタイムアウトしない。
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
  if timeout < 0:
    return err(DeviceNotFound)

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
  const ProcName = &"{ModName}::connect"
  proc restartScan(self: BleNim) {.async.} =
    discard await self.startStopScan(active = self.scan.active, enable = true,
        filterDuplicates = self.scan.filter, filterPolicy = self.scan.filterPolicy)

  var needScanRestart = false
  await self.scanLock.acquire()
  defer: self.scanLock.release()
  if self.scan.enable:
    # BT85x 制限
    # Centralとして接続中 && Scan中 && 接続開始側 の状態の組合せをサポートしない
    # -> Scan を停止する
    if not await self.startStopScan(active = self.scan.active, enable = false,
        filterDuplicates = self.scan.filter, filterPolicy = self.scan.filterPolicy):
      let errmsg = &"! {ProcName}: failed to stop scanning."
      syslog.error(errmsg)
      return
    needScanRestart = true
  let client_res = await self.ble.gattConnect(connParams, timeout = timeout)
  if client_res.isErr:
    discard await self.ble.gattCommonConnectCancelIns()
    if needScanRestart:
      await self.restartScan()
    return err(client_res.error)
  let res = new Gatt
  res.gatt = client_res.get()
  res.peer = connParams.peer
  res.connected = true
  res.ble = self
  self.tblGatt[res.peer] = res
  result = ok(res)
  if needScanRestart:
    if self.scan.filterPolicy == ScanFilterPolicy.WhitelistOnly:
      ## WhiteListOny で Scan している場合
      ## 負荷が少ないので自動で Scan を再開する
      await self.restartScan()

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
  ## - unpair: 同時にペアリング情報の消去を行う。
  if self.gatt.isNil:
    let errmsg = "! Gatt::disconnect: already disconnected."
    syslog.error(errmsg)
    return
  discard await self.gatt.disconnect()
  if unpair:
    discard await self.ble.removeRemoteCollectionKeys(self.peer)
  let peer = self.peer
  if self.ble.tblGatt.hasKey(peer):
    self.ble.tblGatt.del(peer)
  self.connected = false
  self.gatt = nil

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc isConnected*(self: Gatt): bool =
  result = self.connected

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc bdAddress*(self: Gatt): string =
  ## GATT 接続先の Bluetooth Address を取得する。
  result = self.peer.stringValue

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
proc writeGattChar*(self: Gatt, handle: uint16, value: seq[uint8|char]|string,
    withResponse = true): Future[Result[bool, ErrorCode]] {.async.} =
  ## キャラクタリスティック値を書き込む (ハンドル指定)
  if withResponse:
    result = await self.gatt.gattWriteCharacteristicValue(handle, value)
  else:
    result = await self.gatt.gattWriteWithoutResponse(handle, value)

proc writeGattChar*(self: Gatt, handle: uint16, value: uint16|uint8,
    withResponse = true): Future[Result[bool, ErrorCode]] {.async.} =
  if withResponse:
    result = await self.gatt.gattWriteCharacteristicValue(handle, value)
  else:
    result = await self.gatt.gattWriteWithoutResponse(handle, value)

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
  ## ディスクリプタ値を書き込む (ハンドル指定)
  result = await self.gatt.gattWriteCharacteristicDescriptors(handle, desc)

proc writeGattDescriptor*(self: Gatt, handle: uint16, desc: CCC):
    Future[Result[bool, ErrorCode]] {.async.} =
  result = await self.gatt.gattWriteCharacteristicDescriptors(handle, desc.uint16)

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
