import std/asyncdispatch
import std/options
import std/strformat
import nim_nucleus/submodule

type
  ScanState = object
    active: bool
    enable: bool
  BleNimObj = object
    ble: BleClient
    running: bool
    scan: ScanState
    eventQueue: AsyncQueue[string]
  BleNim* = ref BleNimObj
  PeripheralInfo* = object
    bdAddr*: uint16
    bdAddrStr*: string
    rssi*: int

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newBleNim*(debug = false): BleNim =
  new result
  result.ble = newBleClient(debug)

# ------------------------------------------------------------------------------
# Initialize Core
# ------------------------------------------------------------------------------
proc init*(self: BleNim): Future[bool] {.async.} =
  result = await self.ble.initBTM()

# ------------------------------------------------------------------------------
# API: Start/Stop Scanning
# ------------------------------------------------------------------------------
proc startStopScan*(self: BleNim, active: bool, enable: bool):
    Future[bool] {.async.} =
  if enable == self.scan.enable:
    if active != self.scan.active:
      syslog.error("! startStopScan: Another type of scan is already in progress.")
    else:
      result = true
    return

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc waitAdvertise*(self: BleNim): Future[Option[PeripheralInfo]] {.async.} =
  if not self.scan.enable:
    return

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc run(self: BleNim) {.async.} =
  self.running = true
  while true:
    await sleepAsync(1000)


when isMainModule:
  import app
  try:
    waitFor asyncMain()
  except:
    let e = getCurrentException()
    echo e.getStackTrace()
