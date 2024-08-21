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

# ------------------------------------------------------------------------------
# 1.3.18 LE ローカルセキュリティ 設定通知
# ------------------------------------------------------------------------------
proc parseLocalSecurityPropertyEvent*(payload: string): Option[LocalSecurity] =
  const procName = "parseLocalSecurityPropertyEvent"
  if not checkPayloadLen(procName, payload, 12):
    return
  try:
    var res: LocalSecurity
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = getBdAddr(payload, 3)
    res.auth = payload.getU8(9).Authentication
    res.encKeySize = payload.getU8(10)
    res.authorized = if payload.getU8(11).Authorization == Authorization.Completed: true
        else: false
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.19 LE LTK 受信通知
# ------------------------------------------------------------------------------
proc parseLtkReceiveEvent*(payload: string): Option[PeerLtk] =
  const procName = "parseLtkReceiveEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: PeerLtk
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.ltk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.20 LE EDIV Rand 受信通知
# ------------------------------------------------------------------------------
proc parseEdivRandReceiveEvent*(payload: string): Option[PeerEdivRand] =
  const procName = "parseEdivRandReceiveEvent"
  if not checkPayloadLen(procName, payload, 19):
    return
  try:
    var res: PeerEdivRand
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    res.ediv = payload.getLe16(9)
    payload.getLeArray(res.rand, 11, 8)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.22 LE Address Information 受信通知
# ------------------------------------------------------------------------------
proc parseAddressInfoReceiveEvent*(payload: string): Option[PeerAddressInfo] =
  const procName = "parseAddressInfoReceiveEvent"
  if not checkPayloadLen(procName, payload, 16):
    return
  try:
    var res: PeerAddressInfo
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    res.peerId.addrType = payload.getU8(9).AddrType
    res.peerId.address = payload.getBdAddr(10)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.23 LE CSRK 受信通知
# ------------------------------------------------------------------------------
proc parseCsrkReceiveEvent*(payload: string): Option[PeerCsrk] =
  const procName = "parseCsrkReceiveEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: PeerCsrk
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.csrk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.24 LE LTK 送信通知
# ------------------------------------------------------------------------------
proc parseLtkSendEvent*(payload: string): Option[PeerLtk] =
  const procName = "parseLtkSendEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: PeerLtk
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.ltk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.25 LE EDIV Rand 送信通知
# ------------------------------------------------------------------------------
proc parseEdivRandSendEvent*(payload: string): Option[PeerEdivRand] =
  const procName = "parseEdivRandSendEvent"
  if not checkPayloadLen(procName, payload, 19):
    return
  try:
    var res: PeerEdivRand
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    res.ediv = payload.getLe16(9)
    payload.getLeArray(res.rand, 11, 8)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.26 LE IRK 送信通知
# ------------------------------------------------------------------------------
proc parseIrkSendEvent*(payload: string): Option[LocalIrk] =
  const procName = "parseIrkSendEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: LocalIrk
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.irk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.27 LE Address Information 送信通知
# ------------------------------------------------------------------------------
proc parseAddressInfoSendEvent*(payload: string): Option[LocalAddr] =
  const procName = "parseAddressInfoSendEvent"
  if not checkPayloadLen(procName, payload, 9):
    return
  try:
    var res: LocalAddr
    res.addrType = payload.getU8(2).AddrType
    res.address = payload.getBdAddr(3)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.28 LE CSRK 送信通知
# ------------------------------------------------------------------------------
proc parseCsrkSendEvent*(payload: string): Option[PeerCsrk] =
  const procName = "parseCsrkSendEvent"
  if not checkPayloadLen(procName, payload, 25):
    return
  try:
    var res: PeerCsrk
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    payload.getLeArray(res.csrk, 9, 16)
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)

# ------------------------------------------------------------------------------
# 1.3.29 LE 認証完了通知
# ------------------------------------------------------------------------------
proc parseAuthenticationCompleteEvent*(payload: string): Option[PeerAddr] =
  const procName = "parseAuthenticationCompleteEvent"
  if not checkPayloadLen(procName, payload, 9):
    return
  try:
    var res: PeerAddr
    res.addrType = payload.getU8(2).AddrType
    res.address = payload.getBdAddr(3)
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
    res.peer.addrType = payload.getU8(2).AddrType
    res.peer.address = payload.getBdAddr(3)
    res.smReason = payload.getU8(9).SmReason
    result = some(res)
  except:
    let err = getCurrentExceptionMsg()
    let errmsg = &"! {procName}: caught exception, {err}"
    syslog.error(errmsg)
