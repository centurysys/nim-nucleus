import std/locks
import std/net
import std/options
import std/os
import std/osproc
import std/posix
import std/sequtils
import std/strformat
import std/times
import argparse
import results
import ../nim_nucleuspkg/ble/btm
import ../nim_nucleuspkg/ble/util
import ../nim_nucleuspkg/ble/core/opc
import ../nim_nucleuspkg/ble/common/app_parameters
import ../nim_nucleuspkg/lib/syslog

type
  BtmServerObj = object
    callbackInitialized: bool
    btmMode: BtmMode
    btmStarted: bool
    debugBtm: bool
    enableSnoop: bool
    serverSock: Socket
    clientSock: Socket
  BtmServer = ref BtmServerObj
  AppOptions = object
    path: string
    host: Option[string]
    port: Option[Port]
    debug: bool
    logging: bool
    snoop: bool
    remove: bool
  BtmResult {.pure, size: sizeof(uint8).} = enum
    Ok = 0x00'u8
    InternalError = 0x01'u8
    BtModuleError = 0xf6'u8
    Unknown = 0xff'u8
  RespBootCompleted = object
    btmResult: BtmResult
    mode: BtmMode
    version: uint16
    bdAddr: uint64
    bdAddrStr: string
  SignalException = object of OSError

var
  lock: Lock
  btmInitialized: bool
  sock_opt: Option[Socket]
  bdAddrStr: string
  logCmdRecv: bool

const
  SigExceptionStr = "Signal Received"
  StatFile = "/tmp/.btmd_running"
  FailedCountFile = "/tmp/.btmd_init_failed"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc incrementFailCount(): int =
  if fileExists(FailedCountFile):
    try:
      result = FailedCountFile.readFile.strip.parseInt()
    except:
      discard
  result.inc()
  writeFile(FailedCountFile, $result)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc registerSignalHandler(sig: int, fn: proc(x: cint) {.noconv.}) =
  var newAction: Sigaction
  newAction.sa_handler = fn
  discard sigemptyset(newAction.sa_mask)
  discard sigaction(cint(sig), newAction, nil)

#---------------------------------------------------------------------
#
#---------------------------------------------------------------------
proc sig_handler(signum: cint) {.noconv.} =
  let sig: string = case signum
    of 2:
      "SIGINT"
    of 15:
      "SIGTERM"
    else:
      $signum
  raise newException(SignalException, &"{SigExceptionStr}, {$sig}.")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseCompleteEvent(buf: string): Option[RespBootCompleted] =
  if buf.len != 12:
    return
  var
    res: RespBootCompleted
    btmResult: BtmResult
    btmMode: BtmMode
  try:
    {.warning[HoleEnumConv]:off.}
    btmResult = BtmResult(buf.getU8(2).int)
  except:
    btmResult = BtmResult.Unknown
  try:
    {.warning[HoleEnumConv]:off.}
    btmMode = BtmMode(buf.getU8(3).int)
  except:
    btmMode = BtmMode.Shutdown
  res.version = buf.getLe16(4)
  res.bdAddr = buf.getBdAddr(6)
  res.bdAddrStr = res.bdAddr.bdAddr2string()
  res.btmResult = btmResult
  res.mode = btmMode
  result = some(res)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc handleResponseWhenUnconnected(buf: string) =
  let opc = buf.getOpc()
  case opc
  of BTM_D_OPC_MNG_LE_BOOT_COMPLETE_EVT:
    let evt_opt = buf.parseCompleteEvent()
    if evt_opt.isNone:
      return
    let evt = evt_opt.get()
    if evt.btmResult == BtmResult.Ok:
      bdAddrStr = evt.bdAddrStr
      btmInitialized = true
      lock.release()
  of BTM_D_OPC_MNG_REQ_ERR_EVT:
    let errType = buf.getU8(2)
    syslog.error(&"! Error detected, ERR type: 0x{errType:02x}.")
    lock.release()
  else:
    echo &"! handleResponseWhenUnconnected: {buf.len} bytes discarded, {hexDump(buf)}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc logCmdResponse(cmdRes: bool, buf: string) =
  let t = if cmdRes: "CMD" else: "RES"
  let dump = buf.hexDump()
  echo &"BTM [{t}]: {buf.len} bytes."
  for line in dump.splitLines.filterIt(it.len > 0):
    echo line

# ------------------------------------------------------------------------------
# BTM Callback
# ------------------------------------------------------------------------------
proc cmdCallback(buf: cstring, buflen: int) =
  if sock_opt.isSome:
    let sock = sock_opt.get()
    let hdr = buflen.uint16
    discard sock.send(addr hdr, hdr.sizeOf)
    discard sock.send(buf, buflen)
    if logCmdRecv:
      let logbuf = $buf
      logCmdResponse(cmdRes = false, logbuf)
  else:
    var s = newString(buflen)
    copyMem(addr s[0], buf, buflen)
    handleResponseWhenUnconnected(s)

# ------------------------------------------------------------------------------
# BTM Callback (debug log)
# ------------------------------------------------------------------------------
proc debugLogCallback(logtext: string) =
  let ts = now().toTime
  let microsec = int64(ts.toUnixFloat * 1000000.0) mod 1000000.int64
  let nowTime = ts.format("yyyy/MM/dd HH:mm:ss")
  let hdr = &"{nowTime}.{microsec:06d}"
  echo &"{hdr} [BTM]: {logtext}"

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBtmServer(opt: AppOptions): BtmServer =
  new result
  result.debugBtm = opt.debug
  result.enableSnoop = opt.snoop
  if opt.remove:
    discard tryRemoveFile(opt.path)
  var sock: Socket
  if opt.port.isNone:
    sock = newSocket(Domain.AF_UNIX, SOCK_STREAM, IPPROTO_IP)
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindUnix(opt.path)
    const permissions = {
        fpUserExec, fpUserRead, fpUserWrite,
        fpGroupExec, fpGroupRead, fpGroupWrite
    }
    setFilePermissions(opt.path, permissions)
  else:
    sock = newSocket(Domain.AF_INET, SOCK_STREAM, IPPROTO_IP)
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(opt.port.get, opt.host.get)
  sock.listen()
  result.serverSock = sock
  lock.initLock()
  lock.acquire()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc initBtm(self: BtmServer): bool =
  if self.btmStarted:
    return true
  if not self.callbackInitialized:
    let res = setCallback(cmdCallback)
    if not res:
      let errmsg = &"! set callback failed with {res}."
      syslog.error(errmsg)
      return
    if self.debugBtm:
      discard setDebugLogCallback(debugLogCallback)
    if self.enableSnoop:
      discard setBtSnoopLog(true, "/tmp", (10 * 1024 * 1024).uint32)
    self.callbackInitialized = true
  let res = btmStart(BtmMode.Normal)
  if not res:
    let errmsg = &"! start BTM failed with {res}."
    syslog.error(errmsg)
    return
  syslog.info("Wait for BTM initialized...")
  lock.acquire()
  if not btmInitialized:
    let count = incrementFailCount()
    syslog.error(&"BTM initialize failed (count: {count}), quit.")
    self.serverSock.close()
    if count >= 3:
      syslog.error("! reboot...")
      discard execCmd("shutdown -r now")
    quit(1)
  syslog.info(&"BTM initialized, BD ADDRESS: {bdAddrStr}")
  self.btmStarted = true
  registerSignalHandler(SIGINT, sig_handler)
  writeFile(StatFile, "")
  result = true

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc deInitBtm(self: BtmServer): bool {.used.} =
  if not self.btmStarted:
    return true
  let res = btmStart(BtmMode.Shutdown)
  if res:
    self.btmStarted = false
    btmInitialized = false
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
    if logCmdRecv:
      logCmdResponse(cmdRes = true, buf)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc waitClient(self: BtmServer) =
  var sock: Socket
  self.serverSock.accept(sock)
  syslog.info("client application connected.")
  self.clientSock = sock
  sock_opt = some(sock)
  self.handleClientRecv()
  syslog.info("client application disconnected.")
  self.clientSock = nil
  sock_opt = none(Socket)
  sock.close()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc rotateSnoopLog(self: BtmServer) =
  let nowDt = now().format("yyyyMMdd'_'HHmmss")
  let filename = &"/tmp/btsnoop_{nowDt}.log"
  try:
    moveFile("/tmp/btsnoop_hci0.log", filename)
    let logmsg = &"rename btsnoop logfile to {filename}."
    syslog.info(logmsg)
  except:
    let err = getCurrentExceptionMsg()
    syslog.error(&"! rotateSnoopLog: caught exception, \"{err}\"")

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc run(self: BtmServer) =
  while true:
    let initialized = self.initBtm()
    if not initialized:
      sleep(2000)
      continue
    self.waitClient()
    if self.enableSnoop:
      self.rotateSnoopLog()
    let res = self.deInitBtm()
    if not res:
      let logmsg = "failed to finalize BTM."
      syslog.error(logmsg)
    sleep(1000)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc parseOptions(): AppOptions =
  let p = newParser("btmd"):
    argparse.option("-p", "--path", default = socketPath, help = "bind path")
    argparse.option("-P", "--port", help = "bind port")
    argparse.option("-H", "--host", default = "localhost", help = "bind host")
    argparse.flag("-r", "--remove-if-exists", help = "remove socket if exists")
    argparse.flag("-d", "--debug", help = "enable debug")
    argparse.flag("-l", "--logging", help = "enable logging")
    argparse.flag("-s", "--snoop", help = "enable snoop")
  let opts = p.parse()
  if opts.help:
    quit(0)
  try:
    result.path = opts.path
  except:
    echo &"!!! invalid path"
    quit(1)
  if opts.port.len > 0:
    try:
      let port = opts.port.parseInt.Port
      result.port = some(port)
      if opts.host.len > 0:
        result.host = some(opts.host)
      else:
        result.host = some("localhost")
    except:
      echo &"!!! invalid port, use UNIX domain socket."
  result.remove = opts.removeIfExists
  result.debug = opts.debug
  result.logging = opts.logging
  result.snoop = opts.snoop

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc main(): int =
  let opts = parseOptions()
  logCmdRecv = opts.logging
  let btm = newBtmServer(opts)
  registerSignalHandler(SIGTERM, sig_handler)
  registerSignalHandler(SIGINT, sig_handler)
  try:
    btm.run()
  except:
    let err = getCurrentExceptionMsg()
    if not err.contains(SigExceptionStr):
      let e = getCurrentException()
      let errmsg = &"caught exception, \"{err}\"."
      syslog.error(errmsg)
      let trace = e.getStackTrace()
      for line in trace.splitLines:
        syslog.error(line)
    else:
      syslog.info(err)
  discard btmStart(BtmMode.Shutdown)
  removeFile(opts.path)
  removeFile(StatFile)


when isMainModule:
  openlog("btmd")
  quit main()
