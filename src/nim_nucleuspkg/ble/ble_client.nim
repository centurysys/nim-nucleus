import std/asyncdispatch
import std/asyncnet
import std/deques
import std/nativesockets
import std/options
import std/strformat
import std/strutils
import std/tables
import std/times
import results
import ../lib/asyncsync
import ../lib/errcode
import ../lib/mailbox
import ../lib/syslog
import ./core/gatt_result
import ./core/hci_status
import ./core/opc
import ./gatt/parsers
import ./gatt/types
import ./notifications
import ./util
export results
export opc, mailbox
export GattEventCommon, GattHandleValue, ErrorCode

type
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
    running: bool
    sock: AsyncSocket
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
    peer*: PeerAddr
    cmdMbx: Mailbox[string]
    gattMbx: Mailbox[string]
    gattId*: uint16
    conHandle*: uint16
    features*: uint64
    mailboxes*: GattMailboxes
    mtu*: uint16
    encrypted: bool
    encryptionWait: AsyncLock
    connected: bool
  GattClient* = ref GattClientObj

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc formatTime(dt: DateTime): string {.inline, used.} =
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
# Put to Response Mailbox
# ------------------------------------------------------------------------------
proc putResponse*(self: BleClient, opc: uint16, data: string): Future[bool] {.async.} =
  if not self.mainRespMbx.full:
    let res = await self.mainRespMbx.put(data)
    if res.isOk:
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
    let res = await self.appEventMbx.put(data)
    if res.isOk:
      result = true
  else:
    if not self.mainEventMbx.full:
      self.debugEcho(&"* putEvent: OPC: {opc:04X} --> Main Event Mailbox.")
      let res = await self.mainEventMbx.put(data)
      if res.isOk:
        result = true
    else:
      let errmsg = &"! putEvent: EventQueue is full, discarded OPC: [{opc:04X}] !"
      syslog.error(errmsg)

# ------------------------------------------------------------------------------
# Put to Advertising Mailbox
# ------------------------------------------------------------------------------
proc putAdvertising*(self: BleClient, opc: uint16, data: string): Future[bool] {.async.} =
  if not self.mainAdvMbx.full:
    let res = await self.mainAdvMbx.put(data)
    if res.isOk:
      result = true
  else:
    let errmsg = &"! putAdvertising: AdvQueue is full, discarded OPC: [{opc:04X}] !"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# Wait Response Mailbox
# ------------------------------------------------------------------------------
proc waitResponse*(self: BleClient, timeout: int = 0): Future[Result[string, ErrorCode]]
    {.async.} =
  result = await self.mainRespMbx.get(timeout)
  if result.isErr:
    let err = result.error
    syslog.error(&"! waitResponse: {err}")

# ------------------------------------------------------------------------------
# Clear Response Mailbox (if response exists)
# ------------------------------------------------------------------------------
proc clearResponse*(self: BleClient) {.async.} =
  if self.mainRespMbx.contains:
    discard await self.mainRespMbx.get()

# ------------------------------------------------------------------------------
# Wait Event Mailbox
# ------------------------------------------------------------------------------
proc waitEvent*(self: BleClient, timeout: int = 0): Future[Result[string, ErrorCode]]
    {.async.} =
  result = await self.mainEventMbx.get(timeout)
  if result.isErr:
    let err = result.error
    syslog.error(&"! waitEvent: {err}")

# ------------------------------------------------------------------------------
# Setup Waiting Event for Applications
# ------------------------------------------------------------------------------
proc setupEventsForApplication*(self: BleClient, events: seq[uint16] = @[]) =
  if events.len > 0:
    self.waitingEvents = events
  else:
    self.waitingEvents.setLen(0)

# ------------------------------------------------------------------------------
# Wait Event Mailbox (for Applications)
# ------------------------------------------------------------------------------
proc waitAppEvent*(self: BleClient, events: seq[uint16], timeout: int = 0,
    oneshot = false): Future[Result[string, ErrorCode]] {.async.} =
  if events.len > 0:
    self.waitingEvents = events
    debugEcho(&"==== waitAppEvents: events.len: {events.len}...")
    result = await self.appEventMbx.get(timeout)
  if events.len == 0 or oneshot:
    self.waitingEvents.setLen(0)

# ------------------------------------------------------------------------------
# Wait Advertising
# ------------------------------------------------------------------------------
proc waitAdvertising*(self: BleClient): Future[Result[string, ErrorCode]] {.async.} =
  result = await self.mainAdvMbx.get()

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
    discard await mbx.gattRespMbx.put(cfm)

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
    discard await mbx.gattEventMbx.put(event)

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
    discard await mbx.gattNotifyMbx.put(event)

# ------------------------------------------------------------------------------
# BTM Task: Response Handler
# ------------------------------------------------------------------------------
proc responseHandler(self: BleClient) {.async.} =
  while true:
    let hdr = await self.sock.recv(2)
    let pktlen = hdr.getLe16(0).int
    let response = await self.sock.recv(pktlen)
    if response.len < 3:
      self.debugEcho("! responseHandler: ?????")
      continue
    let opc = response.getOpc()
    let opcKind = opc.opc2kind()
    case opcKind
    of OpcKind.GapAdvertise:
      self.debugEcho(" -> OPC_GAP_ADVERTISING")
      discard await self.putAdvertising(opc, response)
    of OpcKind.MainResponses:
      self.debugEcho(" -> OPC_MAIN_RESPONSES")
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
    if hasPendingOperations():
      poll(1)
    GC_fullCollect()

# ==============================================================================
# BTM Task: Sender
# ==============================================================================
proc taskSender(self: BleClient) {.async.} =
  var
    fut_cmd: Future[Result[string, ErrorCode]]
    fut_gatt: Future[Result[string, ErrorCode]]
  while true:
    var
      payload: string
      isCmd: bool = false
      hdr: uint16
    payload.setLen(0)
    if fut_cmd.isNil:
      fut_cmd = self.cmdMbx.receive()
    if fut_gatt.isNil:
      fut_gatt = self.gattMbx.receive()
    await fut_cmd or fut_gatt
    if fut_cmd.finished:
      let payload_res = fut_cmd.read()
      fut_cmd = nil
      if payload_res.isOk:
        payload = payload_res.get()
        isCmd = true
    if (not isCmd) and fut_gatt.finished:
      let payload_res = fut_gatt.read()
      fut_gatt = nil
      if payload_res.isOk:
        payload = payload_res.get()
      else:
        continue
    if payload.len == 0:
      # ???
      continue
    hdr = payload.len.uint16
    await self.sock.send(addr hdr, hdr.sizeOf)
    await self.sock.send(payload)

proc taskDummy(self: BleClient) {.async.} =
  while true:
    await sleepAsync(10000)

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBleClient*(debug: bool = false, debug_stack: bool = false): BleClient =
  new result
  result.mainAdvMbx = newMailbox[string](10)
  result.mainRespMbx = newMailbox[string](5)
  result.mainEventMbx = newMailbox[string](5)
  result.appEventMbx = newMailbox[string](5)
  result.cmdMbx = newMailbox[string](8)
  result.gattMbx = newMailbox[string](8)
  result.lck = newAsyncLock()
  result.debug = debug
  result.sock = newAsyncSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP)
  asyncCheck result.responseHandler()
  asyncCheck result.taskSender()
  asyncCheck result.taskDummy()

# ------------------------------------------------------------------------------
# Initialize
# ------------------------------------------------------------------------------
proc initBTM*(self: BleClient, path: string): Future[bool] {.async.} =
  try:
    await self.sock.connectUnix(path)
    result = true
  except:
    echo "initBTM exception."
    result = false

# ------------------------------------------------------------------------------
# Send Command
# ------------------------------------------------------------------------------
proc btmSend(self: BleClient, payload: string): Future[Result[bool, ErrorCode]]
    {.async.} =
  await self.clearResponse()
  if payload.len == 0:
    return
  result = await self.cmdMbx.put(payload)

# ------------------------------------------------------------------------------
# API: Send Command
# ------------------------------------------------------------------------------
proc btmSendRecv*(self: BleClient, payload: string, timeout = 0):
    Future[Result[string, ErrorCode]] {.async.} =
  await self.lck.acquire()
  defer: self.lck.release()
  let res = await self.btmSend(payload)
  if res.isErr:
    return err(res.error)
  result = await self.waitResponse(timeout)

# ------------------------------------------------------------------------------
# API: Send Command
# ------------------------------------------------------------------------------
proc btmSendRecv*(self: BleClient, buf: openArray[uint8|char], timeout = 0):
    Future[Result[string, ErrorCode]] {.async.} =
  let payload = buf.toString(buf.len)
  result = await self.btmSendRecv(payload, timeout)

# ------------------------------------------------------------------------------
# API: Send Request/Receive, Check Response
# ------------------------------------------------------------------------------
proc btmRequest*(self: BleClient, procName: string, payload: string,
    expectedOpc: uint16, timeout = 0): Future[bool] {.async.} =
  let payload_res = await self.btmSendRecv(payload, timeout)
  if payload_res.isErr:
    let err = payload_res.error
    let errmsg = &"! {procName}: failed, {err}"
    syslog.error(errmsg)
    return
  let response = payload_res.get()
  let resOpc = response.getOpc(0)
  if resOpc != expectedOpc:
    let errmsg = &"! {procName}: response OPC is mismatch, 0x{resOpc:04x}"
    syslog.error(errmsg)
    return
  let hciCode = response.getu8(2)
  self.debugEcho(&"* {procName}: hciCode: {hciCode}")
  result = hciCode.checkHciStatus(procName)

# ------------------------------------------------------------------------------
# API: Handle Encryption Change
# ------------------------------------------------------------------------------
proc handleEncryptionChange*(self: BleClient, conHandle: uint16, enable: bool):
    Future[bool] {.async.} =
  for gattId, gattClient in self.gattClients.pairs:
    if gattClient.conHandle == conHandle:
      if enable:
        if not gattClient.encrypted:
          gattClient.encrypted = true
          if gattClient.encryptionWait.locked:
            gattClient.encryptionWait.release()
      else:
        if gattClient.encrypted:
          gattClient.encrypted = false
      result = true
      break

# ------------------------------------------------------------------------------
# API: Handle Disconnection
# ------------------------------------------------------------------------------
proc handleDisconnectionComplete*(self: BleClient, conHandle: uint16):
    Future[Option[PeerAddr]] {.async.} =
  for gattId, gattClient in self.gattClients.pairs:
    if gattClient.conHandle == conHandle:
      gattClient.connected = false
      if gattClient.encryptionWait.locked:
        let logmsg = &"* handleDisconnectionComplete: release EncryptionWait lock."
        syslog.info(logmsg)
        gattClient.encrypted = false
        gattClient.encryptionWait.release()
      let peer = gattClient.peer
      result = some(peer)
      break

# ------------------------------------------------------------------------------
# API: Handle Gatt Disconnection
# ------------------------------------------------------------------------------
proc handleGattDisconnection*(self: BleClient, gattId: uint16):
    Future[Option[PeerAddr]] {.async.} =
  let gattClient = self.gattClients.getOrdefault(gattId, nil)
  if gattClient.isNil:
    return
  gattClient.connected = false
  if gattClient.encryptionWait.locked:
    let logmsg = "* handleGattDisconnection: release EncryptionWait lock."
    syslog.info(logmsg)
    gattClient.encrypted = false
    gattClient.encryptionWait.release()
  let peer = gattClient.peer
  result = some(peer)

# ==============================================================================
# GATT Client
# ==============================================================================

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitConfirm*(self: GattClient, timeout = 0): Future[Result[GattConfirm, ErrorCode]]
    {.async.} =
  try:
    let mbx = self.mailboxes.gattRespMbx
    if not self.connected:
      result = err(ErrorCode.Disconnected)
    else:
      result = await mbx.get(timeout)
  except:
    discard

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitEvent*(self: GattClient, timeout = 0): Future[Result[GattEvent, ErrorCode]]
    {.async.} =
  try:
    let mbx = self.mailboxes.gattEventMbx
    if not self.connected:
      result = err(ErrorCode.Disconnected)
    else:
      result = await mbx.get(timeout)
  except:
    discard

# ------------------------------------------------------------------------------
# API:
# ------------------------------------------------------------------------------
proc waitNotify*(self: GattClient, timeout = 0): Future[Result[GattHandleValue, ErrorCode]]
    {.async.} =
  try:
    let mbx = self.mailboxes.gattNotifyMbx
    if not self.connected:
      result = err(ErrorCode.Disconnected)
    else:
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
  let peerAddr = self.peer.address.bdAddr2string()
  let mtu = event.gattExchangeMtuData.serverMtu
  let logmsg = &"* MTU changed: peer {peerAddr}, {mtu} [bytes]"
  syslog.info(logmsg)
  self.mtu = mtu

# ------------------------------------------------------------------------------
# API: GATT Client: Send Instruction -> Wait Confirmwation
# ------------------------------------------------------------------------------
proc gattSend*(self: GattClient, payload: string, expOpc: uint16):
    Future[Result[bool, ErrorCode]] {.async.} =
  if not self.connected:
    syslog.error("! gattSend: GATT Disconnected.")
    return err(ErrorCode.Disconnected)
  let put_res = await self.gattMbx.put(payload)
  if put_res.isErr:
    if put_res.error == ErrorCode.Disconnected:
      syslog.error("! gattSend: GATT Disconnected.")
    return err(put_res.error)
  let mbx_res = await self.waitConfirm()
  if mbx_res.isErr:
    return err(ErrorCode.GattError)
  let res = mbx_res.get()
  if res.opc != expOpc:
    syslog.error(&"! gattSend: OPC in response mismatch, {res.opc:04x} != {expOpc:04x}")
    return err(ErrorCode.OpcMismatch)
  if res.gattResult != 0:
    let gattError = res.gattResult.gattResultToString()
    let errmsg = &"! gattSend: failed, {gattError}"
    syslog.error(errmsg)
    return err(ErrorCode.GattError)
  result = ok(true)

# ------------------------------------------------------------------------------
# API: Send Instrucion -> Wait Event
# ------------------------------------------------------------------------------
proc gattSendRecv*(self: GattClient, payload: string, cfmOpc: uint16, evtOpc: uint16):
    Future[Result[string, ErrorCode]] {.async.} =
  let send_res = await self.gattSend(payload, cfmOpc)
  if send_res.isErr:
    return err(send_res.error)
  while true:
    let response_res = await self.waitEvent()
    if response_res.isErr:
      return err(response_res.error)
    let response = response_res.get()
    let resOpc = response.payload.getOpc()
    if resOpc != evtOpc:
      if resOpc == BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT:
        self.gattHandleExchangeMtuEvent(response.payload)
        continue
      else:
        syslog.error(&"! gattSendRecv: OPC in event mismatch, {resOpc:04x} != {evtOpc:04x}")
        result = err(ErrorCode.OpcMismatch)
        break
    else:
      result = ok(response.payload)
      break

# ------------------------------------------------------------------------------
# API: Send Instrucion -> Wait Event(Multi)
# ------------------------------------------------------------------------------
proc gattSendRecvMulti*(self: GattClient, payload: string, cfmOpc: uint16,
    evtOpc: uint16, endOpc: uint16): Future[Result[seq[string], GattError]] {.async.} =
  let send_res = await self.gattSend(payload, cfmOpc)
  if send_res.isErr:
    return err(send_res.error)
  var payloads = newSeqOfCap[string](5)
  while true:
    let response_res = await self.waitEvent()
    if response_res.isErr:
      return err(response_res.error)
    let response = response_res.get()
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
      result = err(ErrorCode.OpcMismatch)
      return
  result = ok(payloads)

# ------------------------------------------------------------------------------
# API: Wait Encryption Complete
# ------------------------------------------------------------------------------
proc waitEncryptionComplete*(self: GattClient): Future[Result[bool, ErrorCode]]
    {.async.} =
  if self.encrypted:
    return ok(true)
  self.encryptionWait.own()
  await self.encryptionWait.acquire()
  if not self.encrypted:
    # maybe disconnected
    result = err(ErrorCode.Disconnected)
  else:
    result = ok(true)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc isConnected*(self: GattClient): bool =
  result = self.connected

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
  client.encryptionWait = newAsyncLock()
  client.mailboxes = gattMailboxes
  client.connected = true
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
