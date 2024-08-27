import std/asyncdispatch
import std/deques
import std/options
import std/strformat
import std/strutils
import std/tables
import ../lib/asyncsync
import ../lib/mailbox
import ../lib/syslog
import ./btm
import ./basic/types
import ./core/gatt_result
import ./core/hci_status
import ./core/opc
import ./sm/types
import ./util
export opc
export mailbox

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
    gattRespQueue: Mailbox[GattConfirm]
    gattEventQueue: Mailbox[GattEvent]
    gattNotifyQueue: Mailbox[GattEvent]
  GattQueues* = ref GattQueuesObj
  GattQueuesPtr* = ptr GattQueues
  BleClientObj = object
    debug: bool
    debugBtm: bool
    bmtStarted: bool
    running: bool
    lck: AsyncLock
    event: Event
    callbackInitialized: bool
    btmMode: BtmMode
    localAddr: array[6, uint8]
    cmdQueue: Mailbox[string]
    mainRespQueue: Mailbox[string]
    mainAdvQueue: Mailbox[string]
    mainEventQueue: Mailbox[string]
    waitingEvents: seq[uint16]
    appEventQueue: Mailbox[string]
    tblGattQueues: Table[uint16, GattQueues]
    gattClients: Table[uint16, GattClient]
    tblRemoteDevices: Table[PeerAddr, RemoteCollectionKeys]
  BleClient* = ref BleClientObj
  GattClientObj = object
    bleClient*: BleClient
    cmdQueue: Mailbox[string]
    gattId*: uint16
    conHandle*: uint16
    features*: uint64
    queues*: GattQueues
    mtu*: uint16
  GattClient* = ref GattClientObj

const
  DEQUE_SIZE = 16

var ev: EventObj

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
  zeroMem(df, dl)
  ev.deque.addLast(buf)
  ev.ev.fire()

# ------------------------------------------------------------------------------
# BTM Callback (debug log)
# ------------------------------------------------------------------------------
proc debugLogCallback(ctx: pointer, text: cstring) {.cdecl.} =
  let logtext = ($text).strip()
  if logtext.len > 0:
    let buf = &"[BTM Log]: {logtext}"
    echo buf

# ------------------------------------------------------------------------------
# BTM Callback (error log)
# ------------------------------------------------------------------------------
proc errorLogCallback(ctx: pointer, log: array[8, uint8]) {.cdecl.} =
  return

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
  if opc in self.waitingEvents:
    debugEcho(&"* putEvent: OPC: {opc:04X} --> Application Event Queue.")
    await self.appEventQueue.put(data)
    result = true
  else:
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
proc waitResponse*(self: BleClient, timeout: int = 0): Future[string] {.async.} =
  let res_opt = await self.mainRespQueue.get(timeout)
  if res_opt.isSome:
    result = res_opt.get()

# ------------------------------------------------------------------------------
# Wait Event Queue
# ------------------------------------------------------------------------------
proc waitEvent*(self: BleClient, timeout: int = 0): Future[string] {.async.} =
  let res_opt = await self.mainEventQueue.get(timeout)
  if res_opt.isSome:
    result = res_opt.get()

# ------------------------------------------------------------------------------
# Wait Event Queue (for Applications)
# ------------------------------------------------------------------------------
proc waitAppEvent*(self: BleClient, events: seq[uint16], timeout: int = 0,
    oneshot = false): Future[Option[string]] {.async.} =
  if events.len > 0:
    self.waitingEvents = events
    result = await self.appEventQueue.get(timeout)
  if events.len == 0 or oneshot:
    self.waitingEvents.setLen(0)

# ------------------------------------------------------------------------------
# Wait Advertising
# ------------------------------------------------------------------------------
proc waitAdvertising*(self: BleClient): Future[string] {.async.} =
  let res_opt = await self.mainAdvQueue.get()
  if res_opt.isSome:
    result = res_opt.get()

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
    await queue.gattRespQueue.put(cfm)

# ------------------------------------------------------------------------------
# Handle GATT Event
# ------------------------------------------------------------------------------
proc gattEventHandler(self: BleClient, opc: uint16, response: string) {.async.} =
  if response.len < 4:
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
  if response.len < 4:
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
    let payload_opt = await self.cmdQueue.get()
    if payload_opt.isNone:
      continue
    let payload = payload_opt.get()
    if not self.bmtStarted:
      continue
    self.debugEcho(&"* sender: payload: {hexDump(payload)}")
    await self.lck.acquire()
    let res = BTM_Send(payload.len.cint, cast[ptr uint8](addr payload[0]))
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
proc newEvent(dequeSize: int = DEQUE_SIZE): Event =
  if not ev.initialized:
    ev.ev = newAsyncEv()
    ev.deque = initDeque[string](DEQUE_SIZE)
    ev.initialized = true
  result = addr ev

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBleClient*(debug: bool = false, debug_stack: bool = false): BleClient =
  new result
  result.event = newEvent()
  result.mainAdvQueue = newMailbox[string](10)
  result.mainRespQueue = newMailbox[string](5)
  result.mainEventQueue = newMailbox[string](5)
  result.appEventQueue = newMailbox[string](5)
  result.cmdQueue = newMailbox[string](8)
  result.debug = debug
  result.debugBtm = debug_stack

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
    if self.debugBtm:
      let nullp = cast[pointer](0)
      discard BTM_SetLogOutputCallback(debugLogCallback.BTM_CB_DEBUG_LOG_OUTPUT_FP,
          nullp, errorLogCallback.BTM_CB_ERROR_LOG_OUTPUT_FP, nullp)
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
  let pkt_opt = await self.mainRespQueue.get()
  if pkt_opt.isNone:
    return
  let pkt = pkt_opt.get()
  self.debugEcho(&"--> received: {pkt.len} bytes.")
  self.debugEcho(pkt.hexDump)
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
    debugEcho(&"--> received: {res.hexDump()}")
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
  let resOpc = response.getOpc(0)
  if resOpc != expectedOpc:
    let errmsg = &"! {procName}: response OPC is mismatch, 0x{resOpc:04x}"
    syslog.error(errmsg)
    return
  let hciCode = response.getu8(2)
  self.debugEcho(&"* {procName}: hciCode: {hciCode}")
  result = hciCode.checkHciStatus(procName)

# ------------------------------------------------------------------------------
# Process Event
# ------------------------------------------------------------------------------
proc processEvent*(self: BleClient, opc: uint16, payload: string) {.async.} =
  discard


# ==============================================================================
# GATT Client
# ==============================================================================

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitConfirm*(self: GattClient, timeout = 0): Future[GattConfirm] {.async.} =
  try:
    let queue = self.queues.gattRespQueue
    let res_opt = await queue.get(timeout)
    if res_opt.isSome:
      result = res_opt.get
  except:
    discard

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitEvent*(self: GattClient, timeout = 0): Future[GattEvent] {.async.} =
  try:
    let queue = self.queues.gattEventQueue
    let res_opt = await queue.get(timeout)
    if res_opt.isSome:
      result = res_opt.get()
  except:
    discard

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitNotify*(self: GattClient, timeout = 0): Future[GattEvent] {.async.} =
  try:
    let queue = self.queues.gattNotifyQueue
    let res_opt = await queue.get(timeout)
    if res_opt.isSome:
      result = res_opt.get()
  except:
    discard

# ------------------------------------------------------------------------------
# API: GATT Client: Send Instruction -> Wait Confirmwation
# ------------------------------------------------------------------------------
proc gattSend*(self: GattClient, payload: string, expOpc: uint16):
    Future[bool] {.async.} =
  await self.cmdQueue.put(payload)
  let res = await self.waitConfirm()
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
  if not await self.gattSend(payload, cfmOpc):
    return
  let response = await self.waitEvent()
  let resOpc = response.payload.getOpc()
  if  resOpc != evtOpc:
    syslog.error(&"! gattSendRecv: OPC in event mismatch, {resOpc:04x} != {evtOpc:04x}")
  else:
    result = some(response.payload)

# ------------------------------------------------------------------------------
# API: Send Instrucion -> Wait Event(Multi)
# ------------------------------------------------------------------------------
proc gattSendRecvMulti*(self: GattClient, payload: string, cfmOpc: uint16,
    endOpc: uint16): Future[Option[seq[string]]] {.async.} =
  if not await self.gattSend(payload, cfmOpc):
    return
  var payloads = newSeqOfCap[string](5)
  while true:
    let response = await self.waitEvent()
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
  result.gattRespQueue = newMailbox[GattConfirm](4)
  result.gattEventQueue = newMailbox[GattEvent](16)
  result.gattNotifyQueue = newMailbox[GattEvent](6)

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newGattClient*(self: BleClient, gattId: uint16, conHandle: uint16):
    Option[GattClient] =
  if self.tblGattQueues.hasKey(gattId):
    return
  let client = new GattClient
  let gattQueues = self.newGattQueues(gattId)
  self.tblGattQueues[gattId] = gattQueues
  self.gattClients[gattId] = client
  client.bleClient = self
  client.cmdQueue = self.cmdQueue
  client.gattId = gattId
  client.conHandle = conHandle
  client.queues = gattQueues
  result = some(client)

# ------------------------------------------------------------------------------
# Deregister
# ------------------------------------------------------------------------------
proc deregister*(self: BleClient, client: GattClient): bool =
  let gattId = client.gattId
  if not self.tblGattQueues.hasKey(gattId):
    return
  self.tblGattQueues.del(gattId)
  self.gattClients.del(gattId)
  result = true


when isMainModule:
  let buf = newString(52)
  echo buf.hexDump()
