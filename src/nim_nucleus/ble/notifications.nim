import std/options
import std/strformat
import ./core/opc
import ./gap/parsers
import ./gatt/parsers
import ./sm/parsers
import ./util
import ../lib/syslog

type
  Opc* = range[0 .. 0x4fff]
  Notification* = object
    case opc*: Opc
    #-------------------------
    # GAP
    #-------------------------
    of BTM_D_OPC_BLE_GAP_ADVERTISING_REPORT_EVT:
      # LE Advertising Report 通知 (0x4017)
      advData*: AdvertisingReport
    of BTM_D_OPC_BLE_GAP_CONNECTION_COMPLETE_EVT:
      # LE Enhanced Connection Complete 通知 (0x419F)
      leConData*: ConnectionCompleteEvent
    of BTM_D_OPC_BLE_GAP_DISCONNECTION_COMPLETE_EVT:
      # LE Disconnection Complete 通知 (0x401B)
      leDisconData*: DisconnectionCompleteEvent
    of BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_EVT:
      # LE Connection Update 通知 (0x4032)
      leConUpdateData*: ConnectionUpdateEvent
    of BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_EVT:
      # LE Read Remote Used Features 通知 (0x4035)
      leRemoteUsedFeaturesData*: RemoteUsedFeatures
    of BTM_D_OPC_BLE_GAP_ENCRYPTION_CHANGE_EVT:
      # LE Encryption Change 通知 (0x4037)
      leEncryptionChangeData*: EncryptionChangeEvent
    of BTM_D_OPC_BLE_GAP_ENHANCED_CONNECTION_COMPLETE_EVT:
      # LE Enhanced Connection Complete 通知 (0x419F)
      leEnhConData*: EnhConnectionCompleteEvent
    of BTM_D_OPC_BLE_GAP_CHANNEL_SELECTION_ALGORITHM_EVT:
      # LE Channel Selection Algorithm 通知 (0x41BE)
      leChanAlgData*: ChannelSelAlgorithmReport
    #-------------------------
    # SM
    #-------------------------
    of BTM_D_OPC_BLE_SM_LOCAL_SECURITY_PROPERTY_EVT:
      # LE ローカルセキュリティ設定通知 (0x407C)
      localSecurityData*: LocalSecurity
    of BTM_D_OPC_BLE_SM_LTK_RECEIVE_EVT, BTM_D_OPC_BLE_SM_LTK_SEND_EVT:
      # LE LTK 受信通知 (0x405D) / LE LTK 送信通知 (0x4072)
      peerLtkData*: LtkEvent
    of BTM_D_OPC_BLE_SM_EDIV_RAND_RECEIVE_EVT, BTM_D_OPC_BLE_SM_EDIV_RAND_SEND_EVT:
      # LE EDIV Rand 受信通知 (0x405E) / LE EDIV Rand 送信通知 (0x4073)
      peerEdivRandData*: EdivRandEvent
    of BTM_D_OPC_BLE_SM_IRK_RECEIVE_EVT, BTM_D_OPC_BLE_SM_IRK_SEND_EVT:
      # LE IRK 受信通知 (0x405F) / LE IRK 送信通知 (0x4074)
      peerIrkData*: IrkEvent
    of BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_RECEIVE_EVT,
        BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_SEND_EVT:
      # LE Address Information 受信通知 (0x4070)
      # LE Address Information 送信通知 (0x4075)
      peerAddressInfoData*: AddressInfoEvent
    of BTM_D_OPC_BLE_SM_CSRK_RECEIVE_EVT, BTM_D_OPC_BLE_SM_CSRK_SEND_EVT:
      # LE CSRK 受信通知 (0x4071) / LE CSRK 送信通知 (0x4076)
      peerCsrkData*: CsrkEvent
    of BTM_D_OPC_BLE_SM_AUTHENTICATION_COMPLETE_EVT:
      # LE 認証完了通知 (0x4077)
      authCompleteData*: AuthCompleteEvent
    of BTM_D_OPC_BLE_SM_AUTHENTICATION_FAILED_EVT:
      # LE 認証失敗通知 (0x407B)
      authFailData*: AuthFailInfo
    #-------------------------
    # GATT
    #-------------------------
    of BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT:
      # GATT 接続通知 (0x40B9)
      gattConData*: GattConEvent
    of BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_EVT:
      # GATT 切断通知 (0x40BB)
      gattDisconData*: GattDisconEvent
    of BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT:
      # GATT Exhange MTU 通知 (0x40D1)
      gattExchangeMtuData*: GattExchangeMtuEvent
    else:
      discard
    valid*: bool

# ------------------------------------------------------------------------------
# Parse Event
# ------------------------------------------------------------------------------
proc parseEvent*(payload: string): Option[Notification] =
  if payload.len < 2:
    return
  let opc = payload.getOpc(0).Opc
  case opc:
  #-------------------------
  # GAP
  #-------------------------
  of BTM_D_OPC_BLE_GAP_ADVERTISING_REPORT_EVT:
    let data = payload.parseAdvertisingReport()
    if data.isSome:
      let res = Notification(opc: opc, advData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_CONNECTION_COMPLETE_EVT:
    let data = payload.parseConnectionComplete()
    if data.isSome:
      let res = Notification(opc: opc, leConData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_DISCONNECTION_COMPLETE_EVT:
    let data = payload.parseDisconnectionComplete()
    if data.isSome:
      let res = Notification(opc: opc, leDisconData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_EVT:
    let data = payload.parseConnectionUpdate()
    if data.isSome:
      let res = Notification(opc: opc, leConUpdateData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_EVT:
    let data = payload.parseRemoteUsedFeatures()
    if data.isSome:
      # LE Read Remote Used Features 通知 (0x4035)
      let res = Notification(opc: opc, leRemoteUsedFeaturesData: data.get(),
          valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_ENCRYPTION_CHANGE_EVT:
    let data = payload.parseEncryptionChange()
    if data.isSome:
      let res = Notification(opc: opc, leEncryptionChangeData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_ENHANCED_CONNECTION_COMPLETE_EVT:
    let data = payload.parseEnhConnectionComplete()
    if data.isSome:
      let res = Notification(opc: opc, leEnhConData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_CHANNEL_SELECTION_ALGORITHM_EVT:
    let data = payload.parseChannelSelAlgorithm()
    if data.isSome:
      let res = Notification(opc: opc, leChanAlgData: data.get(), valid: true)
      result = some(res)
  #-------------------------
  # SM
  #-------------------------
  of BTM_D_OPC_BLE_SM_LOCAL_SECURITY_PROPERTY_EVT:
    let data = payload.parseLocalSecurityPropertyEvent()
    if data.isSome:
      let res = Notification(opc: opc, localSecurityData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_LTK_RECEIVE_EVT, BTM_D_OPC_BLE_SM_LTK_SEND_EVT:
    let send = if opc.uint16 == BTM_D_OPC_BLE_SM_LTK_SEND_EVT: true
        else: false
    let data = payload.parseLtkEvent(send)
    if data.isSome:
      let res = Notification(opc: opc, peerLtkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_EDIV_RAND_RECEIVE_EVT, BTM_D_OPC_BLE_SM_EDIV_RAND_SEND_EVT:
    let send = if opc.uint16 == BTM_D_OPC_BLE_SM_EDIV_RAND_SEND_EVT: true
        else: false
    let data = payload.parseEdivRandEvent(send)
    if data.isSome:
      let res = Notification(opc: opc, peerEdivRandData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_IRK_RECEIVE_EVT, BTM_D_OPC_BLE_SM_IRK_SEND_EVT:
    let send = if opc.uint16 == BTM_D_OPC_BLE_SM_IRK_SEND_EVT: true
        else: false
    let data = payload.parseIrkEvent(send)
    if data.isSome:
      let res = Notification(opc: opc, peerIrkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_RECEIVE_EVT,
      BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_SEND_EVT:
    let send = if opc.uint16 == BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_SEND_EVT:
        true else: false
    let data = payload.parseAddressInfoEvent(send)
    if data.isSome:
      let res = Notification(opc: opc, peerAddressInfoData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_CSRK_RECEIVE_EVT, BTM_D_OPC_BLE_SM_CSRK_SEND_EVT:
    let send = if opc.uint16 == BTM_D_OPC_BLE_SM_CSRK_SEND_EVT: true
        else: false
    let data = payload.parseCsrkEvent(send)
    if data.isSome:
      let res = Notification(opc: opc, peerCsrkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_AUTHENTICATION_COMPLETE_EVT:
    let data = payload.parseAuthenticationCompleteEvent()
    if data.isSome:
      let res = Notification(opc: opc, authCompleteData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_AUTHENTICATION_FAILED_EVT:
    let data = payload.parseAuthenticationFailEvent()
    if data.isSome:
      let res = Notification(opc: opc, authFailData: data.get(), valid: true)
      result = some(res)
  #-------------------------
  # GATT
  #-------------------------
  of BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT:
    let data = payload.parseGattCommonConnectEvent()
    if data.isSome:
      let res = Notification(opc: opc, gattConData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_EVT:
    let data = payload.parseGattCommonDisconnectEvent()
    if data.isSome:
      let res = Notification(opc: opc, gattDisconData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT:
    let data = payload.parseGattExchangeMtu()
    if data.isSome:
      let res = Notification(opc: opc, gattExchangeMtuData: data.get(), valid: true)
      result = some(res)
  else:
    let logmsg = &"! parseEvent: unhandled OPC event received, {opc:04X}"
    syslog.warning(logmsg)
