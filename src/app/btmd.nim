import std/net
import std/options
import std/strformat
import std/times
import results
import ../nim_nucleuspkg/ble/btm
import ../nim_nucleuspkg/ble/util
import ../nim_nucleuspkg/lib/syslog
import ../nim_nucleuspkg/lib/mailbox

type
  CallbackMsg = ref object
    timestamp: DateTime
    msg: string
  EventObj = object
    mbox: Mailbox[CallbackMsg]
    initialized: bool
  Event = ptr EventObj
  BtmServerObj = object
    callbackInitialized: bool
    btmMode: BtmMode
    btmStarted: bool
    debugBtm: bool
    event: Event
    btmMbox: Mailbox[CallbackMsg]
    serverSock: Socket
    clientSock: Socket
  BtmServer = ref BtmServerObj
  AppOptions = object
    port: Port

var
  sock_opt: Option[Socket]

# ------------------------------------------------------------------------------
# BTM Callback
# ------------------------------------------------------------------------------
proc cmdCallback(buf: string) =
  if sock_opt.isSome:
    let sock = sock_opt.get()
    let hdr = buf.len.uint16
    discard sock.send(addr hdr, hdr.sizeOf)
    sock.send(buf)
  else:
    echo &"! cmdCallback: {buf.len} bytes discarded."

# ------------------------------------------------------------------------------
# BTM Callback (debug log)
# ------------------------------------------------------------------------------
proc debugLogCallback(logtext: string) =
  #let msg = new CallbackMsg
  #msg.msg = logtext
  #msg.timestamp = now()
  #discard logEv.mbox.putNoWait(msg)
  echo logtext

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBtmServer(opt: AppOptions): BtmServer =
  new result
  result.debugBtm = false
  let sock = newSocket()
  sock.setSockOpt(OptReuseAddr, true)
  sock.bindAddr(opt.port, "localhost")
  sock.listen()
  result.serverSock = sock

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc initBtm(self: BtmServer): bool =
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
    self.callbackInitialized = true
  let res = btmStart(BtmMode.Normal)
  if not res:
    let errmsg = &"! BleClient::init start BTM failed with {res}."
    syslog.error(errmsg)
    return
  self.btmStarted = true
  result = true

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc handleClientRecv(self: BtmServer) =
  while true:
    let hdr = self.clientSock.recv(2)
    if hdr.len == 0:
      break
    let length = hdr.getLe16(0).int
    let buf = self.clientSock.recv(length)
    if buf.len == 0:
      break
    discard btmSend(buf)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc run(self: BtmServer) =
  discard self.initBtm()
  while true:
    var sock: Socket
    self.serverSock.accept(sock)
    self.clientSock = sock
    sock_opt = some(sock)
    self.handleClientRecv()
    self.clientSock = nil
    sock_opt = none(Socket)
    sock.close()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc main(): int =
  let opts = AppOptions(port: Port(5963))
  let btm = newBtmServer(opts)
  btm.run()

when isMainModule:
  quit main()
