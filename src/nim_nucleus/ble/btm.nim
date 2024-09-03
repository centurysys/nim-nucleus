const libName* = "libBTM.so"
{.pragma: libBTM, cdecl, dynlib: libName.}

const
  # BTM API処理結果 (戻り値)
  BTM_OK*: cint = 0
  BTM_ERROR*: cint = -1
  BTM_NO_RESOURCE*: cint = -2
  # BTM起動モード
  BTM_MODE_SHUTDOWN*: cint = -1
  BTM_MODE_NORMAL*: cint = 0
  BTM_MODE_HCI*: cint = 1
  BTM_MODE_BT_LOGO_TEST*: cint = 2
  # 有効・無効設定
  BTM_ENABLED*: cint = 1
  BTM_DISABLED*: cint = 0

  BTM_SNOOP_PATH_LENGTH_MAX*: cint = 255

type
  # コマンドコールバック関数
  BTM_CB_FP* = proc(dl: cint, df: ptr uint8) {.cdecl.}
  # デバッグログ出力コールバック関数
  BTM_CB_DEBUG_LOG_OUTPUT_FP* =
      proc(user_context: pointer, LogText: cstring) {.cdecl.}
  # エラーログ出力コールバック関数
  BTM_CB_ERROR_LOG_OUTPUT_FP* =
      proc(user_context: pointer, a2: array[8, uint8]) {.cdecl.}

# BTM起動
proc BTM_Start*(iBtmMode: cint): cint {.importc, libBTM.}
# コマンドコールバック関数登録
proc BTM_SetCallback*(callback_func: BTM_CB_FP): cint {.importc, libBTM.}
# コマンド送信
proc BTM_Send*(dl: cint, df: ptr uint8): cint {.importc, libBTM.}
# ログ出力コールバック関数登録
proc BTM_SetLogOutputCallback*(callback_func1: BTM_CB_DEBUG_LOG_OUTPUT_FP,
    user_context_d: pointer, callback_func2: BTM_CB_ERROR_LOG_OUTPUT_FP,
    user_context_e: pointer): cint {.importc, libBTM.}
proc BTM_SetBtSnoopLog*(enabled: bool, pbPath: ptr uint8,
    dwMaxSize: uint32): cint {.importc, libBTM.}
