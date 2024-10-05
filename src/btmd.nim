import std/asyncdispatch
import std/deques
import std/asyncnet
import std/strformat
import std/times
import results
import nim_nucleus/ble/btm
import nim_nucleus/ble/util
import nim_nucleus/lib/asyncsync
import nim_nucleus/lib/syslog
import nim_nucleus/lib/mailbox

type
  CallbackMsg = ref object
    timestamp: DateTime
    msg: string
  EventObj = object
    deque: Deque[CallbackMsg]
    ev: AsyncEv
    initialized: bool
  Event = ptr EventObj
  BtmServerObj = object
    callbackInitialized: bool
    btmMode: BtmMode
    btmStarted: bool
    debugBtm: bool
    event: Event
    btmMbox: Mailbox[CallbackMsg]
    serverSock: AsyncSocket
    clientSock: AsyncSocket
  BtmServer* = ref BtmServerObj
  AppOptions = object
    port: Port

const
  DEQUE_SIZE = 128

var
  ev: EventObj
  logEv: EventObj

# ------------------------------------------------------------------------------
# BTM Callback
# ------------------------------------------------------------------------------
proc cmdCallback(buf: string) =
  echo "* cmdCallback"
  let msg = new CallbackMsg
  msg.msg = buf
  ev.deque.addLast(msg)
  ev.ev.fire()

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
# BTM Task: Response Handler
# ------------------------------------------------------------------------------
proc responseHandler(self: BtmServer) {.async.} =
  while true:
    await self.event.ev.wait()
    self.event.ev.clear()
    while self.event.deque.len > 0:
      let msg = self.event.deque.popFirst()
      let response = msg.msg
      if response.len < 3:
        echo("! responseHandler: ?????")
        continue
      echo &"* responseHandler: length: {response.len}"
      discard await self.btmMbox.put(msg)
      if hasPendingOperations():
        poll(1)
    GC_fullCollect()

# ------------------------------------------------------------------------------
# BTM Task: Log Handler
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
proc newBtmServer(opt: AppOptions): BtmServer =
  echo "newBtmServer..."
  new result
  discard initEvent(addr ev)
  discard initEvent(addr logEv)
  result.event = addr ev
  result.btmMbox = newMailbox[CallbackMsg](64)
  let sock = newAsyncSocket()
  sock.setSockOpt(OptReuseAddr, true)
  sock.bindAddr(opt.port, "localhost")
  sock.listen()
  result.serverSock = sock
  echo "--> newBtmServer OK"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc initBtm(self: BtmServer): Future[bool] {.async.} =
  if self.btmStarted:
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
    self.callbackInitialized = true
    asyncCheck self.responseHandler()
  let res = btmStart(BtmMode.Normal)
  if not res:
    let errmsg = &"! BleClient::init start BTM failed with {res}."
    syslog.error(errmsg)
    return
  let pkt_res = await self.btmMbox.get()
  if pkt_res.isErr:
    return
  let pkt = pkt_res.get()
  discard pkt
  self.btmStarted = true
  result = true
  echo "BTM started."

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc handleClientRecv(self: BtmServer) {.async.} =
  while true:
    let hdr = await self.clientSock.recv(2)
    if hdr.len == 0:
      break
    let length = hdr.getLe16(0).int
    echo &"* header: pktlen: {length}"
    let buf = await self.clientSock.recv(length)
    if buf.len == 0:
      break
    echo &"  received len: {buf.len}"
    discard btmSend(buf)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc handleClientSend(self: BtmServer) {.async.} =
  while true:
    let resp_res = await self.btmMbox.get()
    if resp_res.isErr:
      break
    if self.clientSock.isNil:
      continue
    let resp = resp_res.get
    var hdr: array[2, uint8]
    hdr.setLe16(0, resp.msg.len.uint16)
    echo &"--> send {resp.msg.len} bytes to client."
    await self.clientSock.send(addr hdr, 2)
    await self.clientSock.send(resp.msg)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc taskDummy(self: BtmServer) {.async.} =
  while true:
    await sleepAsync(10000)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc run(self: BtmServer) {.async.} =
  asyncCheck self.taskDummy()
  asyncCheck self.responseHandler()
  discard await self.initBtm()
  asyncCheck self.handleClientSend()
  while true:
    echo "*** wait for client."
    let client = await self.serverSock.accept()
    echo "-> client connected."
    self.clientSock = client
    await self.handleClientRecv()
    self.clientSock = nil
    client.close()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc main(): int =
  let opts = AppOptions(port: Port(5963))
  let btm = newBtmServer(opts)
  let fut = btm.run()
  while not fut.finished:
    poll(50)
  fut.read()

when isMainModule:
  quit main()
