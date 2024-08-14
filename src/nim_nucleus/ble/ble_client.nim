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
import ./core/hci_status
import ./core/opc
import ./util

type
  GattId = distinct uint16
  EventObj = object
    deque: Deque[string]
    ev: AsyncEv
    initialized: bool
  Event = ptr EventObj
  GattQueuesObj* = object
    gattId*: uint16
    respQueue*: AsyncQueue[string]
    eventQueue*: AsyncQueue[string]
  GattQueues* = ref GattQueuesObj
  GattQueuesPtr* = ptr GattQueuesObj
  BleClientObj = object
    started: bool
    event: Event
    callbackInitialized: bool
    btmMode: BtmMode
    localAddr: array[6, uint8]
    tblGattQueues: TableRef[GattId, GattQueuesPtr]
    mainRespQueue*: AsyncQueue[string]
    mainEventQueue*: AsyncQueue[string]
  BleClient* = ref BleClientObj
  GattClientObj = object
    ble*: ptr BleClientObj
    gattId*: uint16
  GattClient* = ref GattClientObj

const
  DEQUE_SIZE = 8
  AQUEUE_SIZE = 64

var ev: EventObj

func getOpc(s: string): uint16 =
  result = (s[0].uint16.shl 8) or s[1].uint16

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc dump(x: string): string =
  var s = newSeqOfCap[string](x.len)
  for c in x:
    s.add(&"0x{c.uint8:02x}")
  result = s.join(" ")

# ------------------------------------------------------------------------------
# BTM Callback
# ------------------------------------------------------------------------------
proc callback(dl: cint, df: ptr uint8) {.cdecl.} =
  var buf = newString(dl)
  copyMem(addr buf[0], df, dl)
  ev.deque.addLast(buf)
  ev.ev.fire()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc responseHandler(self: BleClient) {.async.} =
  while true:
    await self.event.ev.wait()
    while self.event.deque.len > 0:
      let event = self.event.deque.popFirst()
      if event.len == 0:
        continue
      let opc = event.getOpc()
      echo &"* OPC: {opc:04X}"
      if opc in OPC_MAIN_RESPONSES:
        await self.mainRespQueue.put(event)
      elif opc in OPC_MAIN_EVENTS:
        await self.mainEventQueue.put(event)
      elif opc in OPC_GATT_CLIENT_CONFIRMATIONS:
        discard
      elif opc in OPC_GATT_CLIENT_EVENTS:
        discard
    self.event.ev.clear()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc newEvent(dequeSize: int = DEQUE_SIZE, aqSize: int = AQUEUE_SIZE): Event =
  if not ev.initialized:
    echo "initialize event.."
    ev.ev = newAsyncEv()
    ev.deque = initDeque[string](DEQUE_SIZE)
    ev.initialized = true
  result = addr ev

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBleClient*(): BleClient =
  new result
  result.event = newEvent()
  result.mainRespQueue = newAsyncQueue[string](5)
  result.mainEventQueue = newAsyncQueue[string](5)

# ------------------------------------------------------------------------------
# API: BTM 初期化
# ------------------------------------------------------------------------------
proc initBTM*(self: BleClient): Future[bool] {.async.} =
  if self.started:
    return true
  if not self.callbackInitialized:
    let res = BTM_SetCallback(callback)
    if res != 0:
      let errmsg = &"! BleClient::init set callback failed with {res}."
      syslog.error(errmsg)
      return
    self.callbackInitialized = true
    asyncCheck self.responseHandler()
  echo "BTM_Start()"
  let res = BTM_Start(BTM_MODE_NORMAL)
  if res != 0:
    let errmsg = &"! BleClient::init start BTM failed with {res}."
    syslog.error(errmsg)
    return
  echo "wait..."
  let pkt = await self.mainRespQueue.get()
  echo &"--> received: {pkt.dump} {pkt.len} bytes."
  self.started = true
  result = true

# ------------------------------------------------------------------------------
# API: Send Command
# ------------------------------------------------------------------------------
proc btmSend*(self: BleClient, payload: string): bool =
  if not self.started:
    return
  let res = BTM_Send(payload.len.cint, cast[ptr uint8](addr payload[0]))
  if res == 0:
    result = true

# ------------------------------------------------------------------------------
# API: Send Command
# ------------------------------------------------------------------------------
proc btmSendRecv*(self: BleClient, payload: string): Future[Option[string]] {.async.} =
  if not self.btmSend(payload):
    return
  let res = await self.mainRespQueue.get()
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
  let resOpc = response.getOpc(0)
  if resOpc != expectedOpc:
    let errmsg = &"! {procName}: response OPC is mismatch, 0x{resOpc:04x}"
    syslog.error(errmsg)
    return
  let hciCode = payload[2].int
  result = hciCode.checkHciStatus(procName)


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
