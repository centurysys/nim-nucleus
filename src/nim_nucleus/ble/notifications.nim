import std/options
import std/strformat
import ./core/opc
import ./gap/parsers
import ./gatt/parsers
import ./sm/parsers
import ./util
import ../lib/syslog

type
  BleEvent* {.pure.} = enum
    GapAdvertising = "GAP Advertising"
    GapConenctionComplete = "GAP Conenction Completed"
    GapDisconnectionComplete = "GAP Disconnection Completed"
    GapConnectionUpdate = "GAP Connection Update"
    GapReadRemoteUsedFeatures = "GAP Read Remote Used Features"
    GapEncryptionChange = "GAP Encryption Change"
    GapEnhancedConnectionComplete = "GAP Enhanced Connection Complete"
    GapChannelSelectionAlgorithm = "GAP Channel Selection Algorithm"
    SmLocalSecurityProperty = "SM Local Security Property"
    SmLtkReceive = "SM LTK Receive"
    SmLtkSend = "SM LTK Send"
    SmEdivRandReceive = "SM EDIV Rand Receive"
    SmEdivRandSend = "SM EDIV Rand Send"
    SmIrkReceive = "SM IRK Receive"
    SmIrkSend = "SM IRK Send"
    SmAddressInformationReceive = "SM Address Information Receive"
    SmAddressInformationSend = "SM Address Information Send"
    SmCsrkReceive = "SM CSRK Receive"
    SmCsrkSend = "SM CSRK Send"
    SmAuthenticationComplete = "SM Authentication Complete"
    SmAuthenticationFailed = "SM Authentication Failed"
    GattCmnConnect = "GATT Connected"
    GattCmnDisconnect = "GAT Disconnected"
    GattExchangeMtu = "GATT Exchange MTU"

type
  Notification* = object
    case event*: BleEvent
    #-------------------------
    # GAP
    #-------------------------
    of GapAdvertising:
      # LE Advertising Report 通知 (0x4017)
      advData*: AdvertisingReport
    of GapConenctionComplete:
      # LE Enhanced Connection Complete 通知 (0x419F)
      leConData*: ConnectionCompleteEvent
    of GapDisconnectionComplete:
      # LE Disconnection Complete 通知 (0x401B)
      leDisconData*: DisconnectionCompleteEvent
    of GapConnectionUpdate:
      # LE Connection Update 通知 (0x4032)
      leConUpdateData*: ConnectionUpdateEvent
    of GapReadRemoteUsedFeatures:
      # LE Read Remote Used Features 通知 (0x4035)
      leRemoteUsedFeaturesData*: RemoteUsedFeatures
    of GapEncryptionChange:
      # LE Encryption Change 通知 (0x4037)
      leEncryptionChangeData*: EncryptionChangeEvent
    of GapEnhancedConnectionComplete:
      # LE Enhanced Connection Complete 通知 (0x419F)
      leEnhConData*: EnhConnectionCompleteEvent
    of GapChannelSelectionAlgorithm:
      # LE Channel Selection Algorithm 通知 (0x41BE)
      leChanAlgData*: ChannelSelAlgorithmReport
    #-------------------------
    # SM
    #-------------------------
    of SmLocalSecurityProperty:
      # LE ローカルセキュリティ設定通知 (0x407C)
      localSecurityData*: LocalSecurity
    of SmLtkReceive, SmLtkSend:
      # LE LTK 受信通知 (0x405D) / LE LTK 送信通知 (0x4072)
      peerLtkData*: LtkEvent
    of SmEdivRandReceive, SmEdivRandSend:
      # LE EDIV Rand 受信通知 (0x405E) / LE EDIV Rand 送信通知 (0x4073)
      peerEdivRandData*: EdivRandEvent
    of SmIrkReceive, SmIrkSend:
      # LE IRK 受信通知 (0x405F) / LE IRK 送信通知 (0x4074)
      peerIrkData*: IrkEvent
    of SmAddressInformationReceive, SmAddressInformationSend:
      # LE Address Information 受信通知 (0x4070)
      # LE Address Information 送信通知 (0x4075)
      peerAddressInfoData*: AddressInfoEvent
    of SmCsrkReceive, SmCsrkSend:
      # LE CSRK 受信通知 (0x4071) / LE CSRK 送信通知 (0x4076)
      peerCsrkData*: CsrkEvent
    of SmAuthenticationComplete:
      # LE 認証完了通知 (0x4077)
      authCompleteData*: AuthCompleteEvent
    of SmAuthenticationFailed:
      # LE 認証失敗通知 (0x407B)
      authFailData*: AuthFailInfo
    #-------------------------
    # GATT
    #-------------------------
    of GattCmnConnect:
      # GATT 接続通知 (0x40B9)
      gattConData*: GattConEvent
    of GattCmnDisconnect:
      # GATT 切断通知 (0x40BB)
      gattDisconData*: GattDisconEvent
    of GattExchangeMtu:
      # GATT Exhange MTU 通知 (0x40D1)
      gattExchangeMtuData*: GattExchangeMtuEvent
    valid*: bool

# ------------------------------------------------------------------------------
# Parse Event
# ------------------------------------------------------------------------------
proc parseEvent*(payload: string): Option[Notification] =
  if payload.len < 2:
    return
  let opc = payload.getOpc(0)
  case opc:
  #-------------------------
  # GAP
  #-------------------------
  of BTM_D_OPC_BLE_GAP_ADVERTISING_REPORT_EVT:
    let data = payload.parseAdvertisingReport()
    if data.isSome:
      let res = Notification(event: GapAdvertising,
          advData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_CONNECTION_COMPLETE_EVT:
    let data = payload.parseConnectionComplete()
    if data.isSome:
      let res = Notification(event: GapConenctionComplete,
          leConData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_DISCONNECTION_COMPLETE_EVT:
    let data = payload.parseDisconnectionComplete()
    if data.isSome:
      let res = Notification(event: GapDisconnectionComplete,
          leDisconData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_EVT:
    let data = payload.parseConnectionUpdate()
    if data.isSome:
      let res = Notification(event: GapConnectionUpdate,
          leConUpdateData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_EVT:
    let data = payload.parseRemoteUsedFeatures()
    if data.isSome:
      # LE Read Remote Used Features 通知 (0x4035)
      let res = Notification(event: GapReadRemoteUsedFeatures,
          leRemoteUsedFeaturesData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_ENCRYPTION_CHANGE_EVT:
    let data = payload.parseEncryptionChange()
    if data.isSome:
      let res = Notification(event: GapEncryptionChange,
          leEncryptionChangeData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_ENHANCED_CONNECTION_COMPLETE_EVT:
    let data = payload.parseEnhConnectionComplete()
    if data.isSome:
      let res = Notification(event: GapEnhancedConnectionComplete,
          leEnhConData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GAP_CHANNEL_SELECTION_ALGORITHM_EVT:
    let data = payload.parseChannelSelAlgorithm()
    if data.isSome:
      let res = Notification(event: GapChannelSelectionAlgorithm,
          leChanAlgData: data.get(), valid: true)
      result = some(res)
  #-------------------------
  # SM
  #-------------------------
  of BTM_D_OPC_BLE_SM_LOCAL_SECURITY_PROPERTY_EVT:
    let data = payload.parseLocalSecurityPropertyEvent()
    if data.isSome:
      let res = Notification(event: SmLocalSecurityProperty,
          localSecurityData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_LTK_RECEIVE_EVT:
    let data = payload.parseLtkEvent(send = false)
    if data.isSome:
      let res = Notification(event: SmLtkReceive,
          peerLtkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_LTK_SEND_EVT:
    let data = payload.parseLtkEvent(send = true)
    if data.isSome:
      let res = Notification(event: SmLtkSend,
          peerLtkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_EDIV_RAND_RECEIVE_EVT:
    let data = payload.parseEdivRandEvent(send = false)
    if data.isSome:
      let res = Notification(event: SmEdivRandReceive,
          peerEdivRandData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_EDIV_RAND_SEND_EVT:
    let data = payload.parseEdivRandEvent(send = true)
    if data.isSome:
      let res = Notification(event: SmEdivRandSend,
          peerEdivRandData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_IRK_RECEIVE_EVT:
    let data = payload.parseIrkEvent(send = false)
    if data.isSome:
      let res = Notification(event: SmIrkReceive,
          peerIrkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_IRK_SEND_EVT:
    let data = payload.parseIrkEvent(send = true)
    if data.isSome:
      let res = Notification(event: SmIrkSend,
          peerIrkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_RECEIVE_EVT:
    let data = payload.parseAddressInfoEvent(send = false)
    if data.isSome:
      let res = Notification(event: SmAddressInformationReceive,
          peerAddressInfoData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_SEND_EVT:
    let data = payload.parseAddressInfoEvent(send = true)
    if data.isSome:
      let res = Notification(event: SmAddressInformationSend,
          peerAddressInfoData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_CSRK_RECEIVE_EVT:
    let data = payload.parseCsrkEvent(send = false)
    if data.isSome:
      let res = Notification(event: SmCsrkReceive,
          peerCsrkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_CSRK_SEND_EVT:
    let data = payload.parseCsrkEvent(send = true)
    if data.isSome:
      let res = Notification(event: SmCsrkSend,
          peerCsrkData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_AUTHENTICATION_COMPLETE_EVT:
    let data = payload.parseAuthenticationCompleteEvent()
    if data.isSome:
      let res = Notification(event: SmAuthenticationComplete,
          authCompleteData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_SM_AUTHENTICATION_FAILED_EVT:
    let data = payload.parseAuthenticationFailEvent()
    if data.isSome:
      let res = Notification(event: SmAuthenticationFailed,
          authFailData: data.get(), valid: true)
      result = some(res)
  #-------------------------
  # GATT
  #-------------------------
  of BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT:
    let data = payload.parseGattCommonConnectEvent()
    if data.isSome:
      let res = Notification(event: GattCmnConnect,
          gattConData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_EVT:
    let data = payload.parseGattCommonDisconnectEvent()
    if data.isSome:
      let res = Notification(event: GattCmnDisconnect,
          gattDisconData: data.get(), valid: true)
      result = some(res)
  of BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT:
    let data = payload.parseGattExchangeMtu()
    if data.isSome:
      let res = Notification(event: GattExchangeMtu,
          gattExchangeMtuData: data.get(), valid: true)
      result = some(res)
  else:
    let logmsg = &"! parseEvent: unhandled OPC event received, {opc:04X}"
    syslog.warning(logmsg)
