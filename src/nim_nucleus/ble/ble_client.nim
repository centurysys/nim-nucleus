import std/asyncdispatch
import std/deques
import std/options
import std/strformat
import std/strutils
import std/tables
import std/times
import ../lib/asyncsync
import ../lib/mailbox
import ../lib/syslog
import ./btm
import ./core/gatt_result
import ./core/hci_status
import ./core/opc
import ./gatt/parsers
import ./gatt/types
import ./notifications
import ./util
export opc
export mailbox
export GattEventCommon, GattHandleValue

type
  CallbackMsg = ref object
    msg: string
    timestamp: DateTime
  EventObj = object
    deque: Deque[CallbackMsg]
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
  GattMailboxesObj* = object
    gattId*: uint16
    gattRespMbx: Mailbox[GattConfirm]
    gattEventMbx: Mailbox[GattEvent]
    gattNotifyMbx: Mailbox[GattHandleValue]
  GattMailboxes* = ref GattMailboxesObj
  GattMailboxesPtr* = ptr GattMailboxes
  BleClientObj = object
    debug: bool
    debugBtm: bool
    bmtStarted: bool
    running: bool
    event: Event
    callbackInitialized: bool
    btmMode: BtmMode
    localAddr: array[6, uint8]
    lck: AsyncLock
    cmdMbx: Mailbox[string]
    gattMbx: Mailbox[string]
    mainRespMbx: Mailbox[string]
    mainAdvMbx: Mailbox[string]
    mainEventMbx: Mailbox[string]
    waitingEvents: seq[uint16]
    appEventMbx: Mailbox[string]
    tblGattMailboxes: Table[uint16, GattMailboxes]
    gattClients: Table[uint16, GattClient]
  BleClient* = ref BleClientObj
  GattClientObj = object
    bleClient*: BleClient
    cmdMbx: Mailbox[string]
    gattMbx: Mailbox[string]
    gattId*: uint16
    conHandle*: uint16
    features*: uint64
    mailboxes*: GattMailboxes
    mtu*: uint16
  GattClient* = ref GattClientObj

const
  DEQUE_SIZE = 128

var
  ev: EventObj
  logEv: EventObj

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `=destroy`(x: BleClientObj) =
  try:
    if x.bmtStarted:
      discard btmStart(BtmMode.Shutdown)
  except:
    discard

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatTime(dt: DateTime): string {.inline.} =
  let t = now().toTime
  let microsec = int64(t.toUnixFloat * 1000000.0) mod 1000000
  let nowTime = t.format("yyyy/MM/dd HH:mm:ss")
  result = &"{nowTime}.{microsec:06d}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc debugEcho*(self: BleClient, msg: string, header = true) =
  if self.debug:
    debugEcho(msg, header)

# ------------------------------------------------------------------------------
# BTM Callback
# ------------------------------------------------------------------------------
proc cmdCallback(buf: seq[byte]) =
  let callbackTime = now()
  let msg = new CallbackMsg
  msg.msg = buf.toString
  msg.timestamp = callbackTime
  ev.deque.addLast(msg)
  ev.ev.fire()
  poll(1)

# ------------------------------------------------------------------------------
# BTM Callback (debug log)
# ------------------------------------------------------------------------------
proc debugLogCallback(logtext: string) =
  let msg = new CallbackMsg
  msg.msg = logtext
  msg.timestamp = now()
  logEv.deque.addLast(msg)
  if not logEv.ev.isSet:
    logev.ev.fire()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc logHandler() {.async.} =
  while true:
    await logEv.ev.wait()
    logEv.ev.clear()
    while logEv.deque.len > 0:
      let msg = logEv.deque.popFirst()
      let microSec = int64(msg.timestamp.toTime.toUnixFloat * 1000000.0) mod 1000000
      let dateTime = msg.timestamp.format("yyyy/MM/dd HH:mm:ss")
      let logmsg = &"[BTM {dateTime}.{microSec:06d}] {msg.msg}"
      echo logmsg

# ------------------------------------------------------------------------------
# Put to Response Mailbox
# ------------------------------------------------------------------------------
proc putResponse*(self: BleClient, opc: uint16, data: string): Future[bool] {.async.} =
  if not self.mainRespMbx.full:
    await self.mainRespMbx.put(data)
    result = true
  else:
    let errmsg = &"! putResponse: ResponseMbx is full, discarded OPC: [{opc:04X}] !"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# Put to Event Mailbox
# ------------------------------------------------------------------------------
proc putEvent*(self: BleClient, opc: uint16, data: string): Future[bool] {.async.} =
  if opc in self.waitingEvents:
    self.debugEcho(&"* putEvent: OPC: {opc:04X} --> Application Event Mailbox.")
    await self.appEventMbx.put(data)
    result = true
  else:
    if not self.mainEventMbx.full:
      self.debugEcho(&"* putEvent: OPC: {opc:04X} --> Main Event Mailbox.")
      await self.mainEventMbx.put(data)
      result = true
    else:
      let errmsg = &"! putEvent: EventQueue is full, discarded OPC: [{opc:04X}] !"
      syslog.error(errmsg)

# ------------------------------------------------------------------------------
# Put to Advertising Mailbox
# ------------------------------------------------------------------------------
proc putAdvertising*(self: BleClient, opc: uint16, data: string): Future[bool] {.async.} =
  if not self.mainAdvMbx.full:
    await self.mainAdvMbx.put(data)
    result = true
  else:
    let errmsg = &"! putAdvertising: AdvQueue is full, discarded OPC: [{opc:04X}] !"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# Wait Response Mailbox
# ------------------------------------------------------------------------------
proc waitResponse*(self: BleClient, timeout: int = 0): Future[string] {.async.} =
  let res_opt = await self.mainRespMbx.get(timeout)
  if res_opt.isSome:
    result = res_opt.get()
  else:
    syslog.error("! waitResponse: timeouted")

# ------------------------------------------------------------------------------
# Clear Response Mailbox (if response exists)
# ------------------------------------------------------------------------------
proc clearResponse*(self: BleClient) {.async.} =
  if self.mainRespMbx.contains:
    discard await self.mainRespMbx.get()

# ------------------------------------------------------------------------------
# Wait Event Mailbox
# ------------------------------------------------------------------------------
proc waitEvent*(self: BleClient, timeout: int = 0): Future[string] {.async.} =
  let res_opt = await self.mainEventMbx.get(timeout)
  if res_opt.isSome:
    result = res_opt.get()
  else:
    syslog.error("! waitEvent: timeouted")

# ------------------------------------------------------------------------------
# Wait Event Mailbox (for Applications)
# ------------------------------------------------------------------------------
proc waitAppEvent*(self: BleClient, events: seq[uint16], timeout: int = 0,
    oneshot = false): Future[Option[string]] {.async.} =
  if events.len > 0:
    self.waitingEvents = events
    result = await self.appEventMbx.get(timeout)
  if events.len == 0 or oneshot:
    self.waitingEvents.setLen(0)

# ------------------------------------------------------------------------------
# Wait Advertising
# ------------------------------------------------------------------------------
proc waitAdvertising*(self: BleClient): Future[string] {.async.} =
  let res_opt = await self.mainAdvMbx.get()
  if res_opt.isSome:
    result = res_opt.get()

# ------------------------------------------------------------------------------
# Handle GATT Confirm
# ------------------------------------------------------------------------------
proc gattResponseHandler(self: BleClient, opc: uint16, response: string) {.async.} =
  if response.len != 6:
    return
  let gattId = response.getLe16(4)
  if self.tblGattMailboxes.hasKey(gattId):
    let mbx = self.tblGattMailboxes[gattId]
    let cfm = new GattConfirm
    cfm.opc = response.getOpc()
    cfm.gattId = gattId
    cfm.gattResult = response.getLeInt16(2)
    await mbx.gattRespMbx.put(cfm)

# ------------------------------------------------------------------------------
# Handle GATT Event
# ------------------------------------------------------------------------------
proc gattEventHandler(self: BleClient, opc: uint16, response: string) {.async.} =
  if response.len < 4:
    return
  let gattId = response.getLe16(4)
  if self.tblGattMailboxes.hasKey(gattId):
    let mbx = self.tblGattMailboxes[gattId]
    let event = new GattEvent
    event.opc = response.getOpc()
    event.gattId = gattId
    event.gattResult = response.getLeInt16(2)
    event.payload = response
    await mbx.gattEventMbx.put(event)

# ------------------------------------------------------------------------------
# Handle GATT Notify
# ------------------------------------------------------------------------------
proc gattNotifyHandler(self: BleClient, opc: uint16, response: string) {.async.} =
  const procName = "gattNotifyHandler"
  if response.len < 4:
    echo &"! {procName}: response length error"
    return
  let event_opt = parseGattHandleValuesEvent(response)
  if event_opt.isNone:
    # parse error
    return
  let event = event_opt.get()
  let gattId = event.common.gattId
  if self.tblGattMailboxes.hasKey(gattId):
    let mbx = self.tblGattMailboxes[gattId]
    if mbx.gattNotifyMbx.full:
      let errmsg = &"! {procName}: Notify Mailbox (gattID: {gattId}) is full!"
      syslog.error(errmsg)
      return
    await mbx.gattNotifyMbx.put(event)

# ------------------------------------------------------------------------------
# BTM Task: Response Handler
# ------------------------------------------------------------------------------
proc responseHandler(self: BleClient) {.async.} =
  while true:
    await self.event.ev.wait()
    self.event.ev.clear()
    while self.event.deque.len > 0:
      let msg = self.event.deque.popFirst()
      let response = msg.msg
      if response.len < 3:
        self.debugEcho("! responseHandler: ?????")
        continue
      let opc = response.getOpc()
      let opcKind = opc.opc2kind()
      if self.debug:
        let callbackTime = msg.timestamp.formatTime
        self.debugEcho(&"### Response from BTM: OPC: [{opc:04X}] -> {opcKind} ({callbackTime})")
      case opcKind
      of OpcKind.GapAdvertise:
        self.debugEcho(" -> OPC_GAP_ADVERTISING")
        discard await self.putAdvertising(opc, response)
      of OpcKind.MainResponses:
        self.debugEcho(" -> OPC_MAIN_RESPONSES")
        if self.lck.locked:
          self.lck.release()
        discard await self.putResponse(opc, response)
      of OpcKind.MainEvents:
        self.debugEcho(" -> OPC_MAIN_EVENTS")
        discard await self.putEvent(opc, response)
      of OpcKind.GattClientConfirmations:
        self.debugEcho(" -> OPC_GATT_CLIENT_CONFIRMATIONS")
        await self.gattResponseHandler(opc, response)
      of OpcKind.GattClientEvents:
        self.debugEcho(" -> OPC_GATT_CLIENT_EVENTS")
        await self.gattEventHandler(opc, response)
      of OpcKind.GattClientNotifications:
        self.debugEcho(" -> OPC_GATT_CLIENT_NOTIFY")
        await self.gattNotifyHandler(opc, response)
      else:
        self.debugEcho("OPC not found")
        continue
      # 他のtaskにまわす
      if hasPendingOperations():
        poll(1)
      GC_fullCollect()

# ==============================================================================
# BTM Task: Sender
# ==============================================================================
proc taskSender(self: BleClient) {.async.} =
  var
    fut_cmd: Future[Option[string]]
    fut_gatt: Future[Option[string]]
    fut_lck: Future[void]
  while true:
    var
      payload: string
      isCmd: bool = false
    payload.setLen(0)
    if fut_cmd.isNil:
      fut_cmd = self.cmdMbx.receive()
    if fut_gatt.isNil:
      fut_gatt = self.gattMbx.receive()
    if fut_lck.isNil:
      fut_lck = self.lck.acquire()
    await (fut_cmd and fut_lck) or fut_gatt
    if fut_lck.finished and fut_cmd.finished:
      let payload_opt = fut_cmd.read()
      fut_lck.read()
      fut_cmd = nil
      fut_lck = nil
      if payload_opt.isNone:
        self.lck.release()
      else:
        payload = payload_opt.get()
        isCmd = true
    if (not isCmd) and fut_gatt.finished:
      let payload_opt = fut_gatt.read()
      fut_gatt = nil
      if payload_opt.isSome:
        payload = payload_opt.get()
      else:
        continue
    if not self.bmtStarted:
      continue
    if payload.len == 0:
      # ???
      continue
    let res = btmSend(payload)
    if (not res) and isCmd and self.lck.locked:
      # コマンド送信失敗なので Lock をリリースする
      self.lck.release()

proc taskDummy(self: BleClient) {.async.} =
  while true:
    await sleepAsync(10000)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc initEvent(ev: ptr EventObj, dequeSize: int = DEQUE_SIZE): bool =
  if not ev.initialized:
    ev.ev = newAsyncEv()
    ev.deque = initDeque[CallbackMsg](dequeSize)
    ev.initialized = true
    result = true

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBleClient*(debug: bool = false, debug_stack: bool = false): BleClient =
  new result
  discard initEvent(addr ev)
  discard initEvent(addr logEv)
  result.event = addr ev
  result.mainAdvMbx = newMailbox[string](10)
  result.mainRespMbx = newMailbox[string](5)
  result.mainEventMbx = newMailbox[string](5)
  result.appEventMbx = newMailbox[string](5)
  result.cmdMbx = newMailbox[string](8)
  result.gattMbx = newMailbox[string](8)
  result.debug = debug
  result.debugBtm = debug_stack

# ------------------------------------------------------------------------------
# API: BTM 初期化
# ------------------------------------------------------------------------------
proc initBTM*(self: BleClient): Future[bool] {.async.} =
  if self.bmtStarted:
    return true
  if not self.callbackInitialized:
    discard setBtSnoopLog(true, "/tmp", (10 * 1024 * 1024).uint32)
    let res = setCallback(cmdCallback)
    if not res:
      let errmsg = &"! BleClient::init set callback failed with {res}."
      syslog.error(errmsg)
      return
    if self.debugBtm:
      discard setDebugLogCallback(debugLogCallback)
      asyncCheck logHandler()
    self.lck = newAsyncLock()
    self.lck.own()
    self.callbackInitialized = true
    asyncCheck self.taskDummy()
    asyncCheck self.responseHandler()
    asyncCheck self.taskSender()
  self.debugEcho("BTM_Start()")
  let res = btmStart(BtmMode.Normal)
  if not res:
    self.lck.release()
    let errmsg = &"! BleClient::init start BTM failed with {res}."
    syslog.error(errmsg)
    return
  self.debugEcho("wait...")
  let pkt_opt = await self.mainRespMbx.get()
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
  await self.clearResponse()
  if not self.bmtStarted or payload.len == 0:
    return
  await self.cmdMbx.put(payload)
  result = true

# ------------------------------------------------------------------------------
# API: Send Command
# ------------------------------------------------------------------------------
proc btmSendRecv*(self: BleClient, payload: string, timeout = 0):
    Future[Option[string]] {.async.} =
  if not await self.btmSend(payload):
    return
  let res = await self.waitResponse(timeout)
  if res.len > 0:
    result = some(res)

# ------------------------------------------------------------------------------
# API: Send Command
# ------------------------------------------------------------------------------
proc btmSendRecv*(self: BleClient, buf: openArray[uint8|char], timeout = 0):
    Future[Option[string]] {.async.} =
  let payload = buf.toString(buf.len)
  result = await self.btmSendRecv(payload, timeout)

# ------------------------------------------------------------------------------
# API: Send Request/Receive, Check Response
# ------------------------------------------------------------------------------
proc btmRequest*(self: BleClient, procName: string, payload: string,
    expectedOpc: uint16, timeout = 0): Future[bool] {.async.} =
  let res_opt = await self.btmSendRecv(payload, timeout)
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

# ==============================================================================
# GATT Client
# ==============================================================================

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitConfirm*(self: GattClient, timeout = 0): Future[Option[GattConfirm]] {.async.} =
  try:
    let mbx = self.mailboxes.gattRespMbx
    result = await mbx.get(timeout)
  except:
    discard

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitEvent*(self: GattClient, timeout = 0): Future[Option[GattEvent]] {.async.} =
  try:
    let mbx = self.mailboxes.gattEventMbx
    result = await mbx.get(timeout)
  except:
    discard

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitNotify*(self: GattClient, timeout = 0): Future[Option[GattHandleValue]] {.async.} =
  try:
    let mbx = self.mailboxes.gattNotifyMbx
    result = await mbx.get(timeout)
  except:
    let err = getCurrentExceptionMsg()
    echo err

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattHandleExchangeMtuEvent*(self: GattClient, payload: string) =
  let event_opt = payload.parseEvent()
  if event_opt.isNone:
    return
  let event = event_opt.get()
  if event.event != GattExchangeMtu:
    # ???
    return
  let mtu = event.gattExchangeMtuData.serverMtu
  let logmsg = &"* MTU changed, {mtu} [bytes]"
  syslog.info(logmsg)
  self.mtu = mtu

# ------------------------------------------------------------------------------
# API: GATT Client: Send Instruction -> Wait Confirmwation
# ------------------------------------------------------------------------------
proc gattSend*(self: GattClient, payload: string, expOpc: uint16):
    Future[bool] {.async.} =
  await self.gattMbx.put(payload)
  let res_opt = await self.waitConfirm()
  if res_opt.isNone:
    return
  let res = res_opt.get()
  if res.opc != expOpc:
    syslog.error(&"! gattSend: OPC in response mismatch, {res.opc:04x} != {expOpc:04x}")
    return
  if res.gattResult != 0:
    let gattError = res.gattResult.gattResultToString()
    let errmsg = &"! gattSend: failed, {gattError}"
    syslog.error(errmsg)
    return
  result = true

# ------------------------------------------------------------------------------
# API: Send Instrucion -> Wait Event
# ------------------------------------------------------------------------------
proc gattSendRecv*(self: GattClient, payload: string, cfmOpc: uint16, evtOpc: uint16):
    Future[Option[string]] {.async.} =
  if not await self.gattSend(payload, cfmOpc):
    return
  while true:
    let res_opt = await self.waitEvent()
    if res_opt.isNone:
      return
    let response = res_opt.get()
    let resOpc = response.payload.getOpc()
    if  resOpc != evtOpc:
      if resOpc == BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT:
        self.gattHandleExchangeMtuEvent(response.payload)
        continue
      else:
        syslog.error(&"! gattSendRecv: OPC in event mismatch, {resOpc:04x} != {evtOpc:04x}")
        break
    else:
      result = some(response.payload)
      break

# ------------------------------------------------------------------------------
# API: Send Instrucion -> Wait Event(Multi)
# ------------------------------------------------------------------------------
proc gattSendRecvMulti*(self: GattClient, payload: string, cfmOpc: uint16,
    evtOpc: uint16, endOpc: uint16): Future[Option[seq[string]]] {.async.} =
  if not await self.gattSend(payload, cfmOpc):
    return
  var payloads = newSeqOfCap[string](5)
  while true:
    let res_opt = await self.waitEvent()
    if res_opt.isNone:
      return
    let response = res_opt.get()
    if response.gattResult != 0:
      return
    let resOpc = response.payload.getOpc()
    if resOpc == evtOpc:
      payloads.add(response.payload)
    elif resOpc == endOpc:
      payloads.add(response.payload)
      break
    elif resOpc == BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT:
      self.gattHandleExchangeMtuEvent(response.payload)
    else:
      syslog.error(&"! gattSendRecvMulti: OPC in event mismatch, {resOpc:04x}")
      return
  result = some(payloads)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc newGattMailboxes(self: BleClient, gattId: uint16): GattMailboxes =
  new result
  result.gattId = gattID
  result.gattRespMbx = newMailbox[GattConfirm](4)
  result.gattEventMbx = newMailbox[GattEvent](16)
  result.gattNotifyMbx = newMailbox[GattHandleValue](6)

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newGattClient*(self: BleClient, gattId: uint16, conHandle: uint16):
    Option[GattClient] =
  if self.tblGattMailboxes.hasKey(gattId):
    return
  let client = new GattClient
  let gattMailboxes = self.newGattMailboxes(gattId)
  self.tblGattMailboxes[gattId] = gattMailboxes
  self.gattClients[gattId] = client
  client.bleClient = self
  client.cmdMbx = self.cmdMbx
  client.gattMbx = self.gattMbx
  client.gattId = gattId
  client.conHandle = conHandle
  client.mailboxes = gattMailboxes
  result = some(client)

# ------------------------------------------------------------------------------
# Deregister
# ------------------------------------------------------------------------------
proc deregister*(self: BleClient, client: GattClient): bool =
  let gattId = client.gattId
  if not self.tblGattMailboxes.hasKey(gattId):
    return
  self.tblGattMailboxes.del(gattId)
  self.gattClients.del(gattId)
  result = true


when isMainModule:
  let buf = newString(52)
  echo buf.hexDump()
