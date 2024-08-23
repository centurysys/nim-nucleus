import std/asyncdispatch
import std/deques
import std/options
import std/strformat
import std/strutils
import std/tables
import ../lib/asyncsync
import ../lib/syslog
import ./btm
import ./basic/types
import ./core/gatt_result
import ./core/hci_status
import ./core/opc
import ./sm/types
import ./util
export opc
export asyncsync

type
  #GattId = distinct uint16
  EventObj = object
    deque: Deque[string]
    ev: AsyncEv
    initialized: bool
  Event = ptr EventObj
  GattConfirmObj = object
    opc: uint16
    gattId*: uint16
    gattResult*: int16
  GattConfirm* = ref GattConfirmObj
  GattEventObj = object
    opc: uint16
    gattId*: uint16
    gattResult*: int16
    payload*: string
  GattEvent = ref GattEventObj
  GattQueuesObj* = object
    gattId*: uint16
    respQueue: AsyncQueue[GattConfirm]
    gattEventQueue: AsyncQueue[GattEvent]
    gattNotifyQueue: AsyncQueue[GattEvent]
  GattQueues* = ref GattQueuesObj
  GattQueuesPtr* = ptr GattQueuesObj
  BleClientObj = object
    debug: bool
    bmtStarted: bool
    running: bool
    lck: AsyncLock
    event: Event
    callbackInitialized: bool
    btmMode: BtmMode
    localAddr: array[6, uint8]
    cmdQueue: AsyncQueue[string]
    mainRespQueue: AsyncQueue[string]
    mainAdvQueue: AsyncQueue[string]
    mainEventQueue: AsyncQueue[string]
    tblGattQueues: TableRef[uint16, GattQueuesPtr]
    gattClients: seq[ptr GattClient]
    tblRemoteDevices: TableRef[PeerAddr, RemoteCollectionKeys]
  BleClient* = ref BleClientObj
  GattClientObj = object
    ble*: ptr BleClient
    gattId*: uint16
    conHandle*: uint16
    queues*: GattQueues
    mtu*: uint16
  GattClient* = ref GattClientObj

const
  DEQUE_SIZE = 8
  AQUEUE_SIZE = 64

var ev: EventObj

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc dump(x: string): string =
  var s = newSeqOfCap[string](x.len)
  for c in x:
    s.add(&"0x{c.uint8:02x}")
  result = s.join(" ")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc debugEcho*(self: BleClient, msg: string) =
  if self.debug:
    echo msg

# ------------------------------------------------------------------------------
# BTM Callback
# ------------------------------------------------------------------------------
proc callback(dl: cint, df: ptr uint8) {.cdecl.} =
  var buf = newString(dl)
  copyMem(addr buf[0], df, dl)
  ev.deque.addLast(buf)
  ev.ev.fire()

# ------------------------------------------------------------------------------
# Put to Response Queue
# ------------------------------------------------------------------------------
proc putResponse*(self: BleClient, opc: uint16, data: string): Future[bool] {.async.} =
  if not self.mainRespQueue.full:
    await self.mainRespQueue.put(data)
    result = true
  else:
    let errmsg = &"! putResponse: ResponseQueue is full, discarded OPC: [{opc:04X}] !"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# Put to Event Queue
# ------------------------------------------------------------------------------
proc putEvent*(self: BleClient, opc: uint16, data: string): Future[bool] {.async.} =
  if not self.mainEventQueue.full:
    await self.mainEventQueue.put(data)
    result = true
  else:
    let errmsg = &"! putEvent: EventQueue is full, discarded OPC: [{opc:04X}] !"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# Put to Advertising Queue
# ------------------------------------------------------------------------------
proc putAdvertising*(self: BleClient, opc: uint16, data: string): Future[bool] {.async.} =
  if not self.mainAdvQueue.full:
    await self.mainAdvQueue.put(data)
    result = true
  else:
    let errmsg = &"! putAdvertising: AdvQueue is full, discarded OPC: [{opc:04X}] !"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# Wait Response Queue
# ------------------------------------------------------------------------------
proc waitResponse*(self: BleClient): Future[string] {.async.} =
  result = await self.mainRespQueue.get()

# ------------------------------------------------------------------------------
# Wait Event Queue
# ------------------------------------------------------------------------------
proc waitEvent*(self: BleClient): Future[string] {.async.} =
  result = await self.mainEventQueue.get()

# ------------------------------------------------------------------------------
# Wait Advertising
# ------------------------------------------------------------------------------
proc waitAdvertising*(self: BleClient): Future[string] {.async.} =
  result = await self.mainAdvQueue.get()

# ------------------------------------------------------------------------------
# Handle GATT Confirm
# ------------------------------------------------------------------------------
proc gattResponseHandler(self: BleClient, opc: uint16, response: string) {.async.} =
  if response.len != 6:
    return
  let gattId = response.getLe16(4)
  if self.tblGattQueues.hasKey(gattId):
    let queue = self.tblGattQueues[gattId]
    let cfm = new GattConfirm
    cfm.opc = response.getOpc()
    cfm.gattId = gattId
    cfm.gattResult = response.getLeInt16(2)
    await queue.respQueue.put(cfm)

# ------------------------------------------------------------------------------
# Handle GATT Event
# ------------------------------------------------------------------------------
proc gattEventHandler(self: BleClient, opc: uint16, response: string) {.async.} =
  if response.len != 6:
    return
  let gattId = response.getLe16(4)
  if self.tblGattQueues.hasKey(gattId):
    let queue = self.tblGattQueues[gattId]
    let event = new GattEvent
    event.opc = response.getOpc()
    event.gattId = gattId
    event.gattResult = response.getLeInt16(2)
    event.payload = response
    await queue.gattEventQueue.put(event)

# ------------------------------------------------------------------------------
# Handle GATT Notify
# ------------------------------------------------------------------------------
proc gattNotifyHandler(self: BleClient, opc: uint16, response: string) {.async.} =
  if response.len != 6:
    return
  let gattId = response.getLe16(4)
  if self.tblGattQueues.hasKey(gattId):
    let queue = self.tblGattQueues[gattId]
    if queue.gattNotifyQueue.full:
      return
    let event = new GattEvent
    event.opc = response.getOpc()
    event.gattId = gattId
    event.gattResult = response.getLeInt16(2)
    event.payload = response
    await queue.gattNotifyQueue.put(event)

# ------------------------------------------------------------------------------
# BTM Task: Response Handler
# ------------------------------------------------------------------------------
proc responseHandler(self: BleClient) {.async.} =
  proc releaseLock(self: BleClient) =
    if self.lck.locked:
      self.lck.release()

  while true:
    await self.event.ev.wait()
    while self.event.deque.len > 0:
      let response = self.event.deque.popFirst()
      if response.len < 3:
        continue
      let opc = response.getOpc()
      self.debugEcho(&"### Response from BTM: OPC: [{opc:04X}]")
      if opc in OPC_GAP_ADVERTISING:
        self.debugEcho(" -> OPC_GAP_ADVERTISING")
        discard await self.putAdvertising(opc, response)
      elif opc in OPC_MAIN_RESPONSES:
        self.debugEcho(" -> OPC_MAIN_RESPONSES")
        self.releaseLock()
        discard await self.putResponse(opc, response)
      elif opc in OPC_MAIN_EVENTS:
        self.debugEcho(" -> OPC_MAIN_EVENTS")
        discard await self.putEvent(opc, response)
      elif opc in OPC_GATT_CLIENT_CONFIRMATIONS:
        self.debugEcho(" -> OPC_GATT_CLIENT_CONFIRMATIONS")
        self.releaseLock()
        await self.gattResponseHandler(opc, response)
      elif opc in OPC_GATT_CLIENT_EVENTS:
        self.debugEcho(" -> OPC_GATT_CLIENT_EVENTS")
        await self.gattEventHandler(opc, response)
      elif opc in OPC_GATT_CLIENT_NOTIFY:
        self.debugEcho(" -> OPC_GATT_CLIENT_NOTIFY")
        await self.gattNotifyHandler(opc, response)
      else:
        self.debugEcho("OPC not found")
      # 他のtaskにまわす
      await sleepAsync(1)
    self.event.ev.clear()

# ==============================================================================
# BTM Task: Sender
# ==============================================================================
proc taskSender(self: BleClient) {.async.} =
  while true:
    let payload = await self.cmdQueue.get()
    if not self.bmtStarted:
      continue
    self.debugEcho(&"* sender: payload: {dump(payload)}")
    await self.lck.acquire()
    self.debugEcho(" BTM_Send()...")
    let res = BTM_Send(payload.len.cint, cast[ptr uint8](addr payload[0]))
    self.debugEcho(&" BTM_Send() -> result: {res}")
    if res != 0:
      # コマンド送信失敗なので Lock をリリースする
      if self.lck.locked:
        self.lck.release()

proc taskDummy(self: BleClient) {.async.} =
  while true:
    await sleepAsync(10000)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc newEvent(dequeSize: int = DEQUE_SIZE, aqSize: int = AQUEUE_SIZE): Event =
  if not ev.initialized:
    ev.ev = newAsyncEv()
    ev.deque = initDeque[string](DEQUE_SIZE)
    ev.initialized = true
  result = addr ev

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBleClient*(debug: bool = false): BleClient =
  new result
  result.event = newEvent()
  result.mainAdvQueue = newAsyncQueue[string](10)
  result.mainRespQueue = newAsyncQueue[string](5)
  result.mainEventQueue = newAsyncQueue[string](5)
  result.cmdQueue = newAsyncQueue[string](8)
  result.tblRemoteDevices = newTable[PeerAddr, RemoteCollectionKeys](5)
  result.debug = debug

# ------------------------------------------------------------------------------
# API: BTM 初期化
# ------------------------------------------------------------------------------
proc initBTM*(self: BleClient): Future[bool] {.async.} =
  if self.bmtStarted:
    return true
  if not self.callbackInitialized:
    let res = BTM_SetCallback(callback)
    if res != 0:
      let errmsg = &"! BleClient::init set callback failed with {res}."
      syslog.error(errmsg)
      return
    self.lck = newAsyncLock()
    self.callbackInitialized = true
    asyncCheck self.taskDummy()
    asyncCheck self.responseHandler()
    asyncCheck self.taskSender()
  self.debugEcho("BTM_Start()")
  self.lck.own()
  let res = BTM_Start(BTM_MODE_NORMAL)
  if res != 0:
    self.lck.release()
    let errmsg = &"! BleClient::init start BTM failed with {res}."
    syslog.error(errmsg)
    return
  self.debugEcho("wait...")
  let pkt = await self.mainRespQueue.get()
  self.debugEcho(&"--> received: {pkt.dump} {pkt.len} bytes.")
  self.bmtStarted = true
  result = true

# ------------------------------------------------------------------------------
# Send Command
# ------------------------------------------------------------------------------
proc btmSend(self: BleClient, payload: string): Future[bool] {.async.} =
  if not self.bmtStarted:
    return
  await self.cmdQueue.put(payload)
  result = true

# ------------------------------------------------------------------------------
# API: Send Command
# ------------------------------------------------------------------------------
proc btmSendRecv*(self: BleClient, payload: string): Future[Option[string]] {.async.} =
  if not await self.btmSend(payload):
    return
  let res = await self.waitResponse()
  if res.len > 0:
    result = some(res)

# ------------------------------------------------------------------------------
# API: Send Command
# ------------------------------------------------------------------------------
proc btmSendRecv*(self: BleClient, buf: openArray[uint8|char]): Future[Option[string]] {.async.} =
  let payload = buf.toString(buf.len)
  result = await self.btmSendRecv(payload)

# ------------------------------------------------------------------------------
# API: Send Request/Receive, Check Response
# ------------------------------------------------------------------------------
proc btmRequest*(self: BleClient, procName: string, payload: string, expectedOpc: uint16):
    Future[bool] {.async.} =
  let res_opt = await self.btmSendRecv(payload)
  if res_opt.isNone:
    let errmsg = &"! {procName}: failed"
    syslog.error(errmsg)
    return
  let response = res_opt.get()
  self.debugEcho(&"* {procName}: response: {dump(response)}")
  let resOpc = response.getOpc(0)
  if resOpc != expectedOpc:
    let errmsg = &"! {procName}: response OPC is mismatch, 0x{resOpc:04x}"
    syslog.error(errmsg)
    return
  let hciCode = response.getu8(2)
  self.debugEcho(&"* {procName}: hciCode: {hciCode}")
  result = hciCode.checkHciStatus(procName)

# ==============================================================================
# GATT Client
# ==============================================================================

# ------------------------------------------------------------------------------
# GATT Client: Send Instruction -> Wait Confirmwation
# ------------------------------------------------------------------------------
proc gattSend(self: GattClient, gattId: uint16, payload: string, expOpc: uint16):
    Future[bool] {.async.} =
  if not self.ble[].tblGattQueues.hasKey(gattId):
    let errmsg = &"! gattSend: no such GattID: 0x{gattId:04x}."
    syslog.error(errmsg)
    return
  if not await self.ble[].btmSend(payload):
    let errmsg = "! gattSend: send failed."
    syslog.error(errmsg)
    return
  let gattQueues = self.ble[].tblGattQueues[gattId]
  let res = await gattQueues.respQueue.get()
  if res.opc != expOpc:
    syslog.error(&"! gattSend: OPC in response mismatch, {res.opc:04x} != {expOpc:04x}")
    return
  if res.gattResult != 0:
    let gattError = res.gattResult.gattResultToString()
    syslog.error(&"! gattSend: failed, {gattError}")
    return
  result = true

# ------------------------------------------------------------------------------
# API: Send Instrucion -> Wait Event
# ------------------------------------------------------------------------------
proc gattSendRecv*(self: GattClient, payload: string, cfmOpc: uint16, evtOpc: uint16):
    Future[Option[string]] {.async.} =
  let gattId = self.gattId
  if not await self.gattSend(gattId, payload, cfmOpc):
    return
  let gattQueues = self.ble[].tblGattQueues[gattId]
  let response = await gattQueues.gattEventQueue.get()
  if response.payload.getOpc() == evtOpc:
    result = some(response.payload)

# ------------------------------------------------------------------------------
# API: Send Instrucion -> Wait Event(Multi)
# ------------------------------------------------------------------------------
proc gattSendRecvMulti*(self: GattClient, payload: string, cfmOpc: uint16,
    endOpc: uint16): Future[Option[seq[string]]] {.async.} =
  let gattId = self.gattId
  if not await self.gattSend(gattId, payload, cfmOpc):
    return
  let gattQueues = self.ble[].tblGattQueues[gattId]
  var payloads = newSeqOfCap[string](5)
  while true:
    let response = await gattQueues.gattEventQueue.get()
    if response.gattResult != 0:
      return
    payloads.add(response.payload)
    let resOpc = response.payload.getOpc()
    if resOpc == endOpc:
      break
  result = some(payloads)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc newGattQueues(self: BleClient, gattId: uint16): GattQueues =
  new result
  result.gattId = gattID
  result.respQueue = newAsyncQueue[GattConfirm](4)
  result.gattEventQueue = newAsyncQueue[GattEvent](8)
  result.gattNotifyQueue = newAsyncQueue[GattEvent](6)

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newGattClient*(self: BleClient, gattId: uint16): Option[GattClient] =
  if self.tblGattQueues.hasKey(gattId):
    return
  let gattQueues = self.newGattQueues(gattId)
  self.tblGattQueues[gattId] = addr gattQueues[]
  let res = new GattClient
  res.ble = addr self
  res.gattId = gattId
  res.queues = gattQueues
  result = some(res)

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitConfirm*(self: GattClient): Future[GattConfirm] {.async.} =
  try:
    let queue = self.queues.respQueue
    result = await queue.get()
  except:
    discard

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitEvent*(self: GattClient): Future[GattEvent] {.async.} =
  try:
    let queue = self.queues.gattEventQueue
    result = await queue.get()
  except:
    discard

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitNotify*(self: GattClient): Future[GattEvent] {.async.} =
  try:
    let queue = self.queues.gattNotifyQueue
    result = await queue.get()
  except:
    discard


when isMainModule:
  proc dummy() {.async.} =
    while true:
      await sleepAsync(10000)

  proc main() {.async.} =
    asyncCheck dummy()
    let client = newBleClient()
    let res = await client.initBTM()
    echo res

  waitFor main()
