{.push header: "Btm.h".}
var
  # BTM API処理結果 (戻り値)
  BTM_OK* {.importc.}: cint          # 正常終了
  BTM_ERROR* {.importc.}: cint       # 異常終了
  BTM_NO_RESOURCE* {.importc.}: cint # リソース不足
  # BTM起動モード
  BTM_MODE_SHUTDOWN* {.importc.}: cint     # 終了モード
  BTM_MODE_NORMAL* {.importc.}: cint       # 通常モード
  BTM_MODE_HCI* {.importc.}: cint          # HCI モード
  BTM_MODE_BT_LOGO_TEST* {.importc.}: cint # BT ロゴ認証モード
  # 有効・無効設定
  BTM_ENABLED* {.importc.}: cint  # 有効設定
  BTM_DISABLED* {.importc.}: cint # 無効設定

  BTM_SNOOP_PATH_LENGTH_MAX* {.importc.}: cint

type
  # コマンドコールバック関数
  BTM_CB_FP* {.importc.} = proc(dl: cint, df: ptr uint8) {.cdecl.}
  # デバッグログ出力コールバック関数
  BTM_CB_DEBUG_LOG_OUTPUT_FP* {.importc.} =
      proc(user_context: pointer, LogText: cstring) {.cdecl.}
  # エラーログ出力コールバック関数
  BTM_CB_ERROR_LOG_OUTPUT_FP* {.importc.} =
      proc(user_context: pointer, a2: array[8, uint8]) {.cdecl.}

# BTM起動
proc BTM_Start*(iBtmMode: cint): cint {.importc, cdecl.}
# コマンドコールバック関数登録
proc BTM_SetCallback*(callback_func: BTM_CB_FP): cint {.importc, cdecl.}
# コマンド送信
proc BTM_Send*(dl: cint, df: ptr uint8): cint {.importc, cdecl.}
# ログ出力コールバック関数登録
proc BTM_SetLogOutputCallback*(callback_func1: BTM_CB_DEBUG_LOG_OUTPUT_FP,
    user_context_d: pointer, callback_func2: BTM_CB_ERROR_LOG_OUTPUT_FP,
    user_context_e: pointer): cint {.importc, cdecl.}
proc BTM_SetBtSnoopLog*(enabled: bool, pbPath: ptr uint8,
    dwMaxSize: uint32): cint {.importc, cdecl.}
{.pop.}
