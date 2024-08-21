import std/options
import ./core/opc
import ./gap/parsers
import ./gatt/parsers
import ./sm/parsers
import ./util

type
  Opc* = range[0 .. 0x4fff]
  Notification* = object
    case opc*: Opc
    of BTM_D_OPC_BLE_GAP_ADVERTISING_REPORT_EVT:
      # LE Advertising Report 通知 (0x4017)
      advData*: AdvertisingReport
    of BTM_D_OPC_BLE_GAP_DISCONNECTION_COMPLETE_EVT:
      # LE Disconnection Complete 通知 (0x401B)
      leDisconData*: DisconnectionCompleteEvent
    of BTM_D_OPC_BLE_GAP_ENHANCED_CONNECTION_COMPLETE_EVT:
      # LE Enhanced Connection Complete 通知 (0x419F)
      leConData*: EnhConnectionCompleteEvent
    of BTM_D_OPC_BLE_SM_LTK_RECEIVE_EVT:
      # LE LTK 受信通知 (0x405D)
      peerLtkData*: PeerLtk
    of BTM_D_OPC_BLE_SM_EDIV_RAND_RECEIVE_EVT:
      # LE EDIV Rand 受信通知 (0x405E)
      peerEdivRandData*: PeerEdivRand
    of BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT:
      # GATT 接続通知 (0x40B9)
      gattConData*: GattConEvent
    of BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_EVT:
      # GATT 切断通知 (0x40BB)
      gattDisconData*: GattDisconEvent
    else:
      discard
    valid*: bool

# ------------------------------------------------------------------------------
# Parse Event
# ------------------------------------------------------------------------------
proc parseEvent*(payload: string): Option[Notification] =
  let opc = payload.getOpc(0).Opc
  case opc:
  of BTM_D_OPC_BLE_GAP_ADVERTISING_REPORT_EVT:
    let data = payload.parseAdvertisingReport()
    if data.isSome:
      let res = Notification(opc: opc, advData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_DISCONNECTION_COMPLETE_EVT:
    let data = payload.parseDisconnectionComplete()
    if data.isSome:
      let res = Notification(opc: opc, leDisconData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_ENHANCED_CONNECTION_COMPLETE_EVT:
    let data = payload.parseEnhConnectionComplete()
    if data.isSome:
      let res = Notification(opc: opc, leConData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_LTK_RECEIVE_EVT:
    let data = payload.parseLtkReceiveEvent()
    if data.isSome:
      let res = Notification(opc: opc, peerLtkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_EDIV_RAND_RECEIVE_EVT:
    let data = payload.parseEdivRandReceiveEvent()
    if data.isSome:
      let res = Notification(opc: opc, peerEdivRandData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT:
    let data = parseGattCommonConnectEvent(payload)
    if data.isSome:
      let res = Notification(opc: opc, gattConData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_EVT:
    let data = parseGattCommonDisconnectEvent(payload)
    if data.isSome:
      let res = Notification(opc: opc, gattDisconData: data.get(), valid: true)
      result = some(res)
  else:
    return
