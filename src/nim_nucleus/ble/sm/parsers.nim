import std/options
import std/strformat
import ../core/sm_reason
import ./types
import ../util
import ../../lib/syslog
export types

# ==============================================================================
# Event Parsers
# ==============================================================================

func sendReceive(send: bool): string {.inline.} =
  result = if send: "Send" else: "Receive"

# ------------------------------------------------------------------------------
# Common
# ------------------------------------------------------------------------------
proc parsePeer(payload: string): PeerAddr {.inline.} =
  result.addrType = payload.getU8(2).AddrType
  result.address = getBdAddr(payload, 3)

# ------------------------------------------------------------------------------
# 1.3.18 LE ローカルセキュリティ 設定通知
# ------------------------------------------------------------------------------
proc parseLocalSecurityPropertyEvent*(payload: string): Option[LocalSecurity] =
  const procName = "parseLocalSecurityPropertyEvent"
  if not checkPayloadLen(procName, payload, 12):
    return
  try:
    var res: LocalSecurity
    res.peer = payload.parsePeer()
    res.auth = payload.getU8(9).Authentication
    res.encKeySize = payload.getU8(10)
    res.authorization = if payload.getU8(11).Authorization == Authorization.Completed:
        true else: false
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# LE LTK 受信/送信通知
# ------------------------------------------------------------------------------
proc parseLtkEvent*(payload: string, send: bool): Option[LtkEvent] =
  let procName = &"parseLtk{send.sendReceive}Event"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: LtkEvent
    res.peer = payload.parsePeer()
    payload.getLeArray(res.ltk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.19 LE LTK 受信通知
# ------------------------------------------------------------------------------
proc parseLtkReceiveEvent*(payload: string): Option[LtkEvent] =
  result = payload.parseLtkEvent(false)

# ------------------------------------------------------------------------------
# 1.3.24 LE LTK 送信通知
# ------------------------------------------------------------------------------
proc parseLtkSendEvent*(payload: string): Option[LtkEvent] =
  result = payload.parseLtkEvent(true)

# ------------------------------------------------------------------------------
# LE EDIV Rand 受信/送信通知
# ------------------------------------------------------------------------------
proc parseEdivRandEvent*(payload: string, send: bool): Option[EdivRandEvent] =
  let procName = &"parseEdivRand{send.sendReceive}Event"
  if not checkPayloadLen(procName, payload, 19):
    return
  try:
    var res: EdivRandEvent
    res.peer = payload.parsePeer()
    res.ediv = payload.getLe16(9)
    payload.getLeArray(res.rand, 11, 8)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.20 LE EDIV Rand 受信通知
# ------------------------------------------------------------------------------
proc parseEdivRandReceiveEvent*(payload: string): Option[EdivRandEvent] =
  result = payload.parseEdivRandEvent(false)

# ------------------------------------------------------------------------------
# 1.3.25 LE EDIV Rand 送信通知
# ------------------------------------------------------------------------------
proc parseEdivRandSendEvent*(payload: string): Option[EdivRandEvent] =
  result = payload.parseEdivRandEvent(true)

# ------------------------------------------------------------------------------
# LE IRK 受信/送信通知
# ------------------------------------------------------------------------------
proc parseIrkEvent*(payload: string, send: bool): Option[IrkEvent] =
  let procName = &"parseIrk{send.sendReceive}Event"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: IrkEvent
    res.peer = payload.parsePeer()
    payload.getLeArray(res.irk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.21 LE IRK 受信通知
# ------------------------------------------------------------------------------
proc parseIrkReceiveEvent*(payload: string): Option[IrkEvent] =
  result = payload.parseIrkEvent(false)

# ------------------------------------------------------------------------------
# 1.3.26 LE IRK 送信通知
# ------------------------------------------------------------------------------
proc parseIrkSendEvent*(payload: string): Option[IrkEvent] =
  result = payload.parseIrkEvent(true)

# ------------------------------------------------------------------------------
# 1.3.22 LE Address Information 受信通知
# ------------------------------------------------------------------------------
proc parseAddressInfoReceiveEvent*(payload: string): Option[AddressInfoEvent] =
  let procName = "parseAddressInfoReceiveEvent"
  if not checkPayloadLen(procName, payload, 16):
    return
  try:
    var res: AddressInfoEvent
    res.peer = payload.parsePeer()
    res.peerId.addrType = payload.getU8(9).AddrType
    res.peerId.address = payload.getBdAddr(10)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.27 LE Address Information 送信通知
# ------------------------------------------------------------------------------
proc parseAddressInfoSendEvent*(payload: string): Option[AddressInfoEvent] =
  let procName = "parseAddressInfoSendEvent"
  if not checkPayloadLen(procName, payload, 9):
    return
  try:
    var res: AddressInfoEvent
    res.peer = payload.parsePeer()
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# LE CSRK 受信/送信通知
# ------------------------------------------------------------------------------
proc parseCsrkEvent*(payload: string, send: bool): Option[CsrkEvent] =
  let procName = &"parseCsrk{send.sendReceive}Event"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: CsrkEvent
    res.peer = payload.parsePeer()
    payload.getLeArray(res.csrk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.23 LE CSRK 受信通知
# ------------------------------------------------------------------------------
proc parseCsrkReceiveEvent*(payload: string): Option[CsrkEvent] =
  result = payload.parseCsrkEvent(false)

# ------------------------------------------------------------------------------
# 1.3.28 LE CSRK 送信通知
# ------------------------------------------------------------------------------
proc parseCsrkSendEvent*(payload: string): Option[CsrkEvent] =
  result = payload.parseCsrkEvent(true)

# ------------------------------------------------------------------------------
# 1.3.29 LE 認証完了通知
# ------------------------------------------------------------------------------
proc parseAuthenticationCompleteEvent*(payload: string): Option[AuthCompleteEvent] =
  const procName = "parseAuthenticationCompleteEvent"
  if not checkPayloadLen(procName, payload, 9):
    return
  try:
    var res: AuthCompleteEvent
    res.peer = payload.parsePeer()
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.34 LE 認証失敗通知
# ------------------------------------------------------------------------------
proc parseAuthenticationFailEvent*(payload: string): Option[AuthFailInfo] =
  const procName = "parseAuthenticationFailEvent"
  if not checkPayloadLen(procName, payload, 10):
    return
  try:
    var res: AuthFailInfo
    res.peer = payload.parsePeer()
    res.smReason = payload.getU8(9).SmReason
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)
