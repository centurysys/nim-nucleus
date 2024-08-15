import std/strformat
import std/tables

const
  gattCode2string = {
    1: ["BLE_GATT_LOWER_DISCED", "下位層で切断された"],
    2: ["BLE_GATT_ALREADY_REGISTER", "登録済み"],
    0: ["BLE_GATT_POS_RESULT", "成功"],
    -1: ["BLE_GATT_NEG_RESULT", "失敗"],
    -2: ["BLE_GATT_INVALID_ID", "無効な ID"],
    -3: ["BLE_GATT_NO_CONNECTION", "未接続"],
    -4: ["BLE_GATT_NO_RESOURCE", "BT ミドルウェアのリソース不足"],
    -5: ["BLE_GATT_INVALID_PARAMETER", "不正なパラメータ"],
    -6: ["BLE_GATT_CONNECTED", "すでに接続済み、または接続処理中である"],
    -8: ["BLE_GATT_L2_CONNECT_NEG", "L2CAP 接続失敗"],
    -9: ["BLE_GATT_L2_DISCONNECTING", "すでに切断処理中である"],
    -10: ["BLE_GATT_L2_DISCONNECTED", "L2CAP 未接続"],
    -12: ["BLE_GATT_INVALID_SYNTAX", "文法エラー"],
    -15: ["BLE_GATT_TMO_SERVICBLE_REQ", "タイムアウト"],
    -16: ["BLE_GATT_MAX_CONNECTION", "許容最大数接続済み"],
    -17: ["BLE_GATT_ANOTHER_REQUEST", "他の要求を実行中"],
    -18: ["BLE_GATT_INVALID_GAP_PRIVACY", "不正な Peripheral Privacy Flag"],
    -19: ["BLE_GATT_INVALID_SIGN", "不正な署名"],
    -101: ["BLE_GATT_INVALID_HANDLE", ""],
    -102: ["BLE_GATT_READ_NOT_PERMITTED", ""],
    -103: ["BLE_GATT_WRITBLE_NOT_PERMITTED", ""],
    -105: ["BLE_GATT_INSUFFICIENT_AUTHENTICATION", ""],
    -106: ["BLE_GATT_REQUEST_NOT_SUPPORTED", ""],
    -107: ["BLE_GATT_INVALID_OFFSET", ""],
    -108: ["BLE_GATT_INSUFFICIENT_AUTHORIZATION", ""],
    -109: ["BLE_GATT_PREPARBLE_QUEUBLE_FULL", ""],
    -110: ["BLE_GATT_ATTRIBUTBLE_NOT_FOUND", ""],
    -111: ["BLE_GATT_ATTRIBUTBLE_NOT_LONG", ""],
    -112: ["BLE_GATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE", ""],
    -113: ["BLE_GATT_INVALID_ATTRIBUTBLE_VALUE_LENGTH", ""],
    -114: ["BLE_GATT_UNLIKELY_ERROR", ""],
    -115: ["BLE_GATT_INSUFFICIENT_ENCRYPTION", ""],
    -116: ["BLE_GATT_UNSUPPORTED_GROUP_TYPE", ""],
    -117: ["BLE_GATT_INSUFFICIENT_RESOURCE", ""],
    -352: ["BLE_GATT_WRITBLE_REQ_REJECTED", ""],
    -353: ["BLE_GATT_CL_CHAR_CONFIG_DESC_IMPROPER_CONFIGURED", ""],
    -354: ["BLE_GATT_PRO_ALREADY_IN_PROGRESS", ""],
    -355: ["BLE_GATT_OUT_OF_RANGE", ""],
    -400: ["BLE_GATTDB_NO_RESOURCE", "データベース用リソース不足"],
    -402: ["BLE_GATTDB_NO_MORBLE_BYTE", "領域の限界に達した"],
    -403: ["BLE_GATTDB_NO_MORBLE_ATTR_ID", "割り当て可能な AttributeId の限界に達した"],
    -404: ["BLE_GATTDB_ALREADY_EXIST_ITSELF", "すでに存在している"],
    -405: ["BLE_GATTDB_INVALID_PARAMETER", "パラメータエラー"],
    -406: ["BLE_GATTDB_ALREADY_EXIST_ATTR_ID", "AttributeId 重複"],
    -407: ["BLE_GATTDB_SHORT_BUF", "バッファ不足"],
    -408: ["BLE_GATTDB_ALREADY_RESERVED_HANDLE", "割り当て済みの Handle"]
  }.toTable()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc gattResultToString*(code: int16|int, detail = false): string =
  if code >= -351 and code <= -228:
    let attErr = (-code) mod 100
    result = &"ATT Error: {attErr}"
  else:
    let errinfo = gattCode2string.getOrDefault(code.int)
    if errinfo[0].len == 0:
      # undefined error
      result = &"??? Undefiend GattResult: {code}"
    else:
      if not detail or errinfo[1].len == 0:
        result = &"{errinfo[0]} ({code})"
      else:
        result = &"{errinfo[0]} ({errinfo[1]}) (code: {code})"


when isMainModule:
  let gattRes = -17
  echo gattResultToString(gattRes)
  echo gattResultToString(gattRes, detail = true)
