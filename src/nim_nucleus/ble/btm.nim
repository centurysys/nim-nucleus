import std/os
import std/strutils

const libName = "libBTM.so"
{.pragma: libBTM, importc, cdecl, dynlib: libName.}

const
  # BTM API処理結果 (戻り値)
  BTM_OK*: cint = 0
  BTM_ERROR*: cint = -1
  BTM_NO_RESOURCE*: cint = -2
  # BTM起動モード
  BTM_MODE_SHUTDOWN: cint = -1
  BTM_MODE_NORMAL: cint = 0
  BTM_MODE_HCI: cint = 1
  BTM_MODE_BT_LOGO_TEST: cint = 2
  # 有効・無効設定
  BTM_ENABLED*: cint = 1
  BTM_DISABLED*: cint = 0

  BTM_SNOOP_PATH_LENGTH_MAX*: cint = 255

type
  # コマンドコールバック関数
  BTM_CB_FP = proc(dl: cint, df: ptr uint8) {.cdecl.}
  # デバッグログ出力コールバック関数
  BTM_CB_DEBUG_LOG_OUTPUT_FP =
      proc(user_context: pointer, LogText: cstring) {.cdecl.}
  # エラーログ出力コールバック関数
  BTM_CB_ERROR_LOG_OUTPUT_FP =
      proc(user_context: pointer, a2: array[8, uint8]) {.cdecl.}

# BTM起動
proc BTM_Start(iBtmMode: cint): cint {.libBTM.}
# コマンドコールバック関数登録
proc BTM_SetCallback(callback_func: BTM_CB_FP): cint {.libBTM.}
# コマンド送信
proc BTM_Send(dl: cint, df: ptr uint8): cint {.libBTM.}
# ログ出力コールバック関数登録
proc BTM_SetLogOutputCallback(callback_func1: BTM_CB_DEBUG_LOG_OUTPUT_FP,
    user_context_d: pointer, callback_func2: BTM_CB_ERROR_LOG_OUTPUT_FP,
    user_context_e: pointer): cint {.libBTM.}
proc BTM_SetBtSnoopLog(enabled: bool, pbPath: ptr uint8, dwMaxSize: uint32):
    cint {.libBTM.}

type
  BtmMode* {.pure.} = enum
    Shutdown = BTM_MODE_SHUTDOWN.int
    Normal = BTM_MODE_NORMAL.int
    Hci = BTM_MODE_HCI.int
    BtLogoTest = BTM_MODE_BT_LOGO_TEST.int

var
  cmdCallbackFunc: proc(buf: seq[byte])
  logCallbackFunc: proc(buf: string)

# ------------------------------------------------------------------------------
# BTM Callback (command)
# ------------------------------------------------------------------------------
proc btmCallback(dl: cint, df: ptr uint8) {.cdecl.} =
  if cmdCallbackFunc.isNil:
    return
  var buf = newSeq[byte](dl)
  copyMem(addr buf[0], df, dl)
  cmdCallbackFunc(buf)

# ------------------------------------------------------------------------------
# BTM Callback (debug log)
# ------------------------------------------------------------------------------
proc logCallback(ctx: pointer, text: cstring) {.cdecl.} =
  if logCallbackFunc.isNil:
    return
  let logtext = ($text).strip()
  if logtext.len > 0:
    logCallbackFunc(logtext)

# ------------------------------------------------------------------------------
# BTM Callback (error log)
# ------------------------------------------------------------------------------
proc errorLogCallback(ctx: pointer, log: array[8, uint8]) {.cdecl.} =
  return

# ------------------------------------------------------------------------------
# API: BTM起動
# ------------------------------------------------------------------------------
proc btmStart*(mode: BtmMode): bool =
  if cmdCallbackFunc.isNil:
    return
  let res = BTM_Start(mode.cint)
  if res == BTM_OK:
    result = true

# ------------------------------------------------------------------------------
# API: コマンドコールバック関数登録
# ------------------------------------------------------------------------------
proc setCallback*(fn: proc(buf: seq[byte])): bool =
  let res = BTM_SetCallback(btmCallback)
  if res == BTM_OK:
    cmdCallbackFunc = fn
    result = true

# ------------------------------------------------------------------------------
# API: ログ出力コールバック関数登録
# ------------------------------------------------------------------------------
proc setDebugLogCallback*(fn: proc(buf: string)): bool =
  let nullp = cast[pointer](0)
  let res = BTM_SetLogOutputCallback(logCallback.BTM_CB_DEBUG_LOG_OUTPUT_FP,
      nullp, errorLogCallback.BTM_CB_ERROR_LOG_OUTPUT_FP, nullp)
  if res == BTM_OK:
    logCallbackFunc = fn
    result = true

# ------------------------------------------------------------------------------
# API: コマンド送信
# ------------------------------------------------------------------------------
proc btmSend*(payload: string|seq[byte]): bool =
  let res = BTM_Send(payload.len.cint, cast[ptr uint8](addr payload[0]))
  if res == 0:
    result = true

# ------------------------------------------------------------------------------
# API: BTSnoop ログ設定
# ------------------------------------------------------------------------------
proc setBtSnoopLog*(enabled: bool, path: string, maxSize: uint32): bool =
  if not path.dirExists:
    return
  let res = BTM_SetBtSnoopLog(enabled, cast[ptr uint8](path.cstring), maxSize)
  if res == BTM_OK:
    result = true
