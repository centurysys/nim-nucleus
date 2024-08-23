import std/sequtils

const
  BTM_D_BLE_ADDR_LEN* = 6
  BTM_D_BLE_SIZE_DEV_NAME* = 249
  BTM_D_BLE_SIZE_LE_FEAT* = 8
  BTM_D_BLE_SIZE_LE_STATES* = 8
  BTM_D_BLE_SIZE_ADV_DATA* = 31
  BTM_D_BLE_SIZE_PRI_ADV_INTERVAL* = 3
  BTM_D_BLE_SIZE_SCAN_RSP_DATA* = 31
  BTM_D_BLE_SIZE_IRK* = 16
  BTM_D_BLE_SIZE_STK* = 16
  BTM_D_BLE_SIZE_LTK* = 16
  BTM_D_BLE_SIZE_ENC_KEY* = 16
  BTM_D_BLE_SIZE_CSRK* = 16
  BTM_D_BLE_SIZE_RAND* = 8
  BTM_D_BLE_SIZE_EDIV* = 2
  BTM_D_BLE_SIZE_CHANNEL_MAP* = 5
  BTM_D_BLE_SIZE_OOB_DATA* = 16
  BTM_D_BLE_SIZE_DHK* = 16
  BTM_D_BLE_MAX_NUM_OF_ADV_REP* = 25
  BTM_D_BLE_EXT_ADV_DATA_LEN_MAX* = 1650
  BTM_D_BLE_GAP_SET_EXT_ADV_ENABLE_SET_NUM* = 0x000000F0
  BTM_D_BLE_GAP_SET_EXT_ADV_ENABLE_SET_LEN* = 4
  BTM_D_BLE_EXT_SCAN_RESP_DATA_LEN_MAX* = 251
  BTM_D_BLE_EXT_ADV_ENV_MAX* = 63
  BTM_D_BLE_NUM_PHY* = 3
  BTM_D_BLE_SCANNING_NUM_PHY* = 2
  BTM_D_BLE_SCAN_PARAM* = 5
  BTM_D_BLE_DEFAULT_FIXED_CH* = 0x00000004
  BTM_D_SEC_MODE_1_LEVEL_1* = 0x00000001
  BTM_D_SEC_MODE_1_LEVEL_2* = 0x00000002
  BTM_D_SEC_MODE_1_LEVEL_4* = 0x00000006
  BTM_D_ENCRYPTION_KEYSIZE_MIN* = 7
  BTM_D_ENCRYPTION_KEYSIZE_MAX* = 16
  BTM_D_GATT_MAX_NUM_OF_ALL_PR_SERVICE* = 8
  BTM_D_GATT_MAX_NUM_OF_PR_SERVICE* = 255
  BTM_D_GATT_MAX_NUM_OF_INC_SERVICE* = 46
  BTM_D_GATT_MAX_NUM_OF_LOCAL_INC_SERVICE* = 23
  BTM_D_GATT_MAX_NUM_OF_LOCAL_INC_FOR_SERVICE* = 1
  BTM_D_GATT_MAX_NUM_OF_CHAR_OF_SERVICE* = 46
  BTM_D_GATT_MAX_NUM_OF_CHAR_BY_UUID* = 46
  BTM_D_GATT_MAX_NUM_OF_CHAR_DESC* = 56
  BTM_D_GATT_MAX_NUM_OF_MULTI_CHARA* = 8
  BTM_D_GATT_MAX_NUM_OF_EXECUTE_HANDLE* = 10
  BTM_D_GATT_SIZE_UUID* = 16
  BTM_D_GATT_SIZE_UUID16* = 2
  BTM_D_GATT_SIZE_UUID128* = 16
  BTM_D_GATT_SIZE_CHARA_VALUE* = 512
  BTM_D_GATT_SIZE_CHARA_VALUE_LIST* = 1022
  BTM_D_GATT_SIZE_MULTI_CHARA_VALUE* = 1023
  BTM_D_GATT_SIZE_CHARA_DESC* = 512
  BTM_D_BLE_OPCODE_BASE* = 0x4000'u16
  BTM_D_BLE_MAX_OPCODE_VALUE* = 0x41FF'u16
  BTM_D_CMD_EVT_MAX_PARAM_LENGTH* = 2048

## コマンドパラメタ長定義
const
  BTM_D_CMN_EVT_NO_PARAM_LEN* = 2
  BTM_D_CMN_RESULT_ONLY_EVT_PARAM_LEN* = 3
  BTM_D_GATT_RESULT_ONLY_EVT_PARAM_LEN* = 4
  BTM_D_GATT_RESULT_AND_ID_ONLY_EVT_PARAM_LEN* = 6
  BTM_D_OPC_MNG_REQ_ERR_EVT* = 0x0050'u16
  BTM_D_MNG_REQ_ERR_EVT_LEN* = 5

## Bluetooth Low Energy 機能 OpCode定義（0x4000～0x4FFF）

## BLE GAP機能( BLE_GAP )
const
  BTM_D_OPC_NONE* = 0xFFFF'u16
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_PARAMETERS_REQ* = 0x4000'u16
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_PARAMETERS_RSP* = 0x4010'u16
  BTM_D_OPC_BLE_GAP_READ_ADVERTISING_CHANNEL_TX_POWER_REQ* = 0x4001'u16
  BTM_D_OPC_BLE_GAP_READ_ADVERTISING_CHANNEL_TX_POWER_RSP* = 0x4011'u16
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_DATA_REQ* = 0x4002'u16
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_DATA_RSP* = 0x4012'u16
  BTM_D_OPC_BLE_GAP_SET_SCAN_RESPONSE_DATA_REQ* = 0x4003'u16
  BTM_D_OPC_BLE_GAP_SET_SCAN_RESPONSE_DATA_RSP* = 0x4013'u16
  BTM_D_OPC_BLE_GAP_SET_ADVERTISE_ENABLE_REQ* = 0x4004'u16
  BTM_D_OPC_BLE_GAP_SET_ADVERTISE_ENABLE_RSP* = 0x4014'u16
  BTM_D_OPC_BLE_GAP_SET_SCAN_PARAMETERS_REQ* = 0x4005'u16
  BTM_D_OPC_BLE_GAP_SET_SCAN_PARAMETERS_RSP* = 0x4015'u16
  BTM_D_OPC_BLE_GAP_SET_SCAN_ENABLE_REQ* = 0x4006'u16
  BTM_D_OPC_BLE_GAP_SET_SCAN_ENABLE_RSP* = 0x4016'u16
  BTM_D_OPC_BLE_GAP_ADVERTISING_REPORT_EVT* = 0x4017'u16
  BTM_D_OPC_BLE_GAP_CONNECTION_COMPLETE_EVT* = 0x4019'u16
  BTM_D_OPC_BLE_GAP_DISCONNECT_INS* = 0x400A'u16
  BTM_D_OPC_BLE_GAP_DISCONNECT_CFM* = 0x401A'u16
  BTM_D_OPC_BLE_GAP_DISCONNECTION_COMPLETE_EVT* = 0x401B'u16
  BTM_D_OPC_BLE_GAP_READ_WHITE_LIST_SIZE_REQ* = 0x400D'u16
  BTM_D_OPC_BLE_GAP_READ_WHITE_LIST_SIZE_RSP* = 0x401D'u16
  BTM_D_OPC_BLE_GAP_CLEAR_WHITE_LIST_REQ* = 0x400E'u16
  BTM_D_OPC_BLE_GAP_CLEAR_WHITE_LIST_RSP* = 0x401E'u16
  BTM_D_OPC_BLE_GAP_ADD_DEVICE_TO_WHITE_LIST_REQ* = 0x400F'u16
  BTM_D_OPC_BLE_GAP_ADD_DEVICE_TO_WHITE_LIST_RSP* = 0x401F'u16
  BTM_D_OPC_BLE_GAP_REMOVE_DEVICE_FROM_WHITE_LIST_REQ* = 0x4020'u16
  BTM_D_OPC_BLE_GAP_REMOVE_DEVICE_FROM_WHITE_LIST_RSP* = 0x4030'u16
  BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_INS* = 0x4021'u16
  BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_CFM* = 0x4031'u16
  BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_EVT* = 0x4032'u16
  BTM_D_OPC_BLE_GAP_SET_HOST_CHANNEL_CLASSIFICATION_REQ* = 0x4023'u16
  BTM_D_OPC_BLE_GAP_SET_HOST_CHANNEL_CLASSIFICATION_RSP* = 0x4033'u16
  BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_INS* = 0x4024'u16
  BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_CFM* = 0x4034'u16
  BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_EVT* = 0x4035'u16
  BTM_D_OPC_BLE_GAP_ENCRYPTION_CHANGE_EVT* = 0x4037'u16
  BTM_D_OPC_BLE_GAP_READ_SUPPORTED_STATES_REQ* = 0x4029'u16
  BTM_D_OPC_BLE_GAP_READ_SUPPORTED_STATES_RSP* = 0x4039'u16
  BTM_D_OPC_BLE_GAP_RSSI_REQ* = 0x402B'u16
  BTM_D_OPC_BLE_GAP_RSSI_RSP* = 0x403B'u16
  BTM_D_OPC_MNG_LE_BOOT_COMPLETE_EVT* = 0x403F'u16
  BTM_D_OPC_BLE_GAP_READ_PHY_REQ* = 0x4168'u16
  BTM_D_OPC_BLE_GAP_READ_PHY_RSP* = 0x4178'u16
  BTM_D_OPC_BLE_GAP_SET_DEFAULT_PHY_REQ* = 0x4169'u16
  BTM_D_OPC_BLE_GAP_SET_DEFAULT_PHY_RSP* = 0x4179'u16
  BTM_D_OPC_BLE_GAP_SET_PHY_INS* = 0x416A'u16
  BTM_D_OPC_BLE_GAP_SET_PHY_CFM* = 0x417A'u16
  BTM_D_OPC_BLE_GAP_PHY_UPDATE_COMPLETE_EVT* = 0x417B'u16
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_SET_RANDOM_ADDRESS_REQ* = 0x416C'u16
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_SET_RANDOM_ADDRESS_RSP* = 0x417C'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_PARAMETERS_REQ* = 0x416D'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_PARAMETERS_RSP* = 0x417D'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_DATA_REQ* = 0x416E'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_DATA_RSP* = 0x417E'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_RESPONSE_DATA_REQ* = 0x416F'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_RESPONSE_DATA_RSP* = 0x417F'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_ENABLE_REQ* = 0x4180'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_ENABLE_RSP* = 0x4190'u16
  BTM_D_OPC_BLE_GAP_ADVERTISING_SET_TERMINATED_EVT* = 0x4191'u16
  BTM_D_OPC_BLE_GAP_SCAN_REQUEST_RECEIVED_EVT* = 0x4192'u16
  BTM_D_OPC_BLE_GAP_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_REQ* = 0x4183'u16
  BTM_D_OPC_BLE_GAP_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_RSP* = 0x4193'u16
  BTM_D_OPC_BLE_GAP_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_REQ* = 0x4184'u16
  BTM_D_OPC_BLE_GAP_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_RSP* = 0x4194'u16
  BTM_D_OPC_BLE_GAP_REMOVE_ADVERTISING_SET_REQ* = 0x4185'u16
  BTM_D_OPC_BLE_GAP_REMOVE_ADVERTISING_SET_RSP* = 0x4195'u16
  BTM_D_OPC_BLE_GAP_CLEAR_ADVERTISING_SETS_REQ* = 0x4186'u16
  BTM_D_OPC_BLE_GAP_CLEAR_ADVERTISING_SETS_RSP* = 0x4196'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_PARAMETERS_REQ* = 0x418A'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_PARAMETERS_RSP* = 0x419A'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_ENABLE_REQ* = 0x418B'u16
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_ENABLE_RSP* = 0x419B'u16
  BTM_D_OPC_BLE_GAP_SCAN_TIMEOUT_EVT* = 0x419C'u16
  BTM_D_OPC_BLE_GAP_EXTENDED_ADVERTISING_REPORT_EVT* = 0x419D'u16
  BTM_D_OPC_BLE_GAP_ENHANCED_CONNECTION_COMPLETE_EVT* = 0x419F'u16
  BTM_D_OPC_BLE_GAP_READ_TRASMIT_POWER_REQ* = 0x41AA'u16
  BTM_D_OPC_BLE_GAP_READ_TRASMIT_POWER_RSP* = 0x41BA'u16
  BTM_D_OPC_BLE_GAP_READ_RF_PATH_COMPENSATION_REQ* = 0x41AB'u16
  BTM_D_OPC_BLE_GAP_READ_RF_PATH_COMPENSATION_RSP* = 0x41BB'u16
  BTM_D_OPC_BLE_GAP_WRITE_RF_PATH_COMPENSATION_REQ* = 0x41AC'u16
  BTM_D_OPC_BLE_GAP_WRITE_RF_PATH_COMPENSATION_RSP* = 0x41BC'u16
  BTM_D_OPC_BLE_GAP_CHANNEL_SELECTION_ALGORITHM_EVT* = 0x41BE'u16

## BLE SM機能( BLE_SM )
const
  BTM_D_OPC_BLE_SM_LOCAL_IO_CAPABILITIES_SET_REQ* = 0x4040'u16
  BTM_D_OPC_BLE_SM_LOCAL_IO_CAPABILITIES_SET_RSP* = 0x4050'u16
  BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_REQ* = 0x4041'u16
  BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_RSP* = 0x4051'u16
  BTM_D_OPC_BLE_SM_PAIRING_INS* = 0x4042'u16
  BTM_D_OPC_BLE_SM_PAIRING_CFM* = 0x4052'u16
  BTM_D_OPC_BLE_SM_DEFAULT_INITIATOR_KEY_DISTRIBUTION_SET_REQ* = 0x4043'u16
  BTM_D_OPC_BLE_SM_DEFAULT_INITIATOR_KEY_DISTRIBUTION_SET_RSP* = 0x4053'u16
  BTM_D_OPC_BLE_SM_LOCAL_DEVICE_KEY_SET_REQ* = 0x4044'u16
  BTM_D_OPC_BLE_SM_LOCAL_DEVICE_KEY_SET_RSP* = 0x4054'u16
  BTM_D_OPC_BLE_SM_REMOTE_COLLECTION_KEY_SET_REQ* = 0x4045'u16
  BTM_D_OPC_BLE_SM_REMOTE_COLLECTION_KEY_SET_RSP* = 0x4055'u16
  BTM_D_OPC_BLE_SM_REMOTE_DISTRIBUTION_KEY_SET_REQ* = 0x4046'u16
  BTM_D_OPC_BLE_SM_REMOTE_DISTRIBUTION_KEY_SET_RSP* = 0x4056'u16
  BTM_D_OPC_BLE_SM_REMOTE_DEVICE_KEY_DELETE_REQ* = 0x4047'u16
  BTM_D_OPC_BLE_SM_REMOTE_DEVICE_KEY_DELETE_RSP* = 0x4057'u16
  BTM_D_OPC_BLE_SM_USER_CONFIRMATION_REQUEST_EVT* = 0x4058'u16
  BTM_D_OPC_BLE_SM_USER_CONFIRMATION_INPUT* = 0x4048'u16
  BTM_D_OPC_BLE_SM_DEFAULT_RESPONDER_KEY_DISTRIBUTION_SET_REQ* = 0x404A'u16
  BTM_D_OPC_BLE_SM_DEFAULT_RESPONDER_KEY_DISTRIBUTION_SET_RSP* = 0x405A'u16
  BTM_D_OPC_BLE_SM_PASSKEY_REQUEST_EVT* = 0x405B'u16
  BTM_D_OPC_BLE_SM_PASSKEY_INPUT* = 0x404B'u16
  BTM_D_OPC_BLE_SM_PASSKEY_DISPLAY_REQUEST_EVT* = 0x405C'u16
  BTM_D_OPC_BLE_SM_LTK_RECEIVE_EVT* = 0x405D'u16
  BTM_D_OPC_BLE_SM_EDIV_RAND_RECEIVE_EVT* = 0x405E'u16
  BTM_D_OPC_BLE_SM_IRK_RECEIVE_EVT* = 0x405F'u16
  BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_RECEIVE_EVT* = 0x4070'u16
  BTM_D_OPC_BLE_SM_CSRK_RECEIVE_EVT* = 0x4071'u16
  BTM_D_OPC_BLE_SM_LTK_SEND_EVT* = 0x4072'u16
  BTM_D_OPC_BLE_SM_EDIV_RAND_SEND_EVT* = 0x4073'u16
  BTM_D_OPC_BLE_SM_IRK_SEND_EVT* = 0x4074'u16
  BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_SEND_EVT* = 0x4075'u16
  BTM_D_OPC_BLE_SM_CSRK_SEND_EVT* = 0x4076'u16
  BTM_D_OPC_BLE_SM_AUTHENTICATION_COMPLETE_EVT* = 0x4077'u16
  BTM_D_OPC_BLE_SM_LOCAL_OOB_DATA_CREATE_REQ* = 0x4068'u16
  BTM_D_OPC_BLE_SM_LOCAL_OOB_DATA_CREATE_RSP* = 0x4078'u16
  BTM_D_OPC_BLE_SM_REMOTE_OOB_DATA_SET_REQ* = 0x4069'u16
  BTM_D_OPC_BLE_SM_REMOTE_OOB_DATA_SET_RSP* = 0x4079'u16
  BTM_D_OPC_BLE_SM_PRIVATE_ADDRESS_RESOLVE_CHECK_REQ* = 0x406A'u16
  BTM_D_OPC_BLE_SM_PRIVATE_ADDRESS_RESOLVE_CHECK_RSP* = 0x407A'u16
  BTM_D_OPC_BLE_SM_AUTHENTICATION_FAILED_EVT* = 0x407B'u16
  BTM_D_OPC_BLE_SM_LOCAL_SECURITY_PROPERTY_EVT* = 0x407C'u16

## BLE GATT機能（サーバー／クライアント共通）( GATT_CMN )
const
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_INS* = 0x40A8'u16
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_CFM* = 0x40B8'u16
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT* = 0x40B9'u16
  BTM_D_OPC_BLE_GATT_CMN_EXTENDED_CONNECT_INS* = 0x40A9'u16
  BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_INS* = 0x40AA'u16
  BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_CFM* = 0x40BA'u16
  BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_EVT* = 0x40BB'u16
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_CANCEL_INS* = 0x40AC'u16
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_CANCEL_CFM* = 0x40BC'u16

## BLE GATTクライアント機能( GATT_C )
const
  BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_INS* = 0x40C0'u16
  BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_CFM* = 0x40D0'u16
  BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT* = 0x40D1'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_INS* = 0x40C2'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_CFM* = 0x40D2'u16
  BTM_D_OPC_BLE_GATT_C_ALL_PRIMARY_SERVICES_EVT* = 0x40D3'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_EVT* = 0x40D4'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_PRIMARY_SERVICES_BY_SERVICE_UUID_INS* = 0x40C5'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_PRIMARY_SERVICES_BY_SERVICE_UUID_CFM* = 0x40D5'u16
  BTM_D_OPC_BLE_GATT_C_PRIMARY_SERVICES_EVT* = 0x40D6'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_PRIMARY_SERVICES_BY_SERVICE_UUID_EVT* = 0x40D7'u16
  BTM_D_OPC_BLE_GATT_C_FIND_INCLUDED_SERVICES_INS* = 0x40C8'u16
  BTM_D_OPC_BLE_GATT_C_FIND_INCLUDED_SERVICES_CFM* = 0x40D8'u16
  BTM_D_OPC_BLE_GATT_C_INCLUDED_SERVICES_EVT* = 0x40D9'u16
  BTM_D_OPC_BLE_GATT_C_FIND_INCLUDED_SERVICES_EVT* = 0x40DA'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_INS* = 0x40CB'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_CFM* = 0x40DB'u16
  BTM_D_OPC_BLE_GATT_C_ALL_CHARACTERISTICS_OF_A_SERVICE_EVT* = 0x40DC'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_EVT* = 0x40DD'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_INS* = 0x40E0'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_CFM* = 0x40F0'u16
  BTM_D_OPC_BLE_GATT_C_CHARACTERISTICS_BY_UUID_EVT* = 0x40F1'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_EVT* = 0x40F2'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_INS* = 0x40E3'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_CFM* = 0x40F3'u16
  BTM_D_OPC_BLE_GATT_C_ALL_CHARACTERISTIC_DESCRIPTORS_EVT* = 0x40F4'u16
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_EVT* = 0x40F5'u16
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_INS* = 0x40E6'u16
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_CFM* = 0x40F6'u16
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_EVT* = 0x40F7'u16
  BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_INS* = 0x40E8'u16
  BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_CFM* = 0x40F8'u16
  BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_EVT* = 0x40F9'u16
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_VALUES_INS* = 0x40EA'u16
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_VALUES_CFM* = 0x40FA'u16
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_VALUES_EVT* = 0x40FB'u16
  BTM_D_OPC_BLE_GATT_C_READ_MULTIPLE_CHARACTERISTIC_VALUES_INS* = 0x40EC'u16
  BTM_D_OPC_BLE_GATT_C_READ_MULTIPLE_CHARACTERISTIC_VALUES_CFM* = 0x40FC'u16
  BTM_D_OPC_BLE_GATT_C_READ_MULTIPLE_CHARACTERISTIC_VALUES_EVT* = 0x40FD'u16
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_INS* = 0x40EE'u16
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_CFM* = 0x40FE'u16
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_EVT* = 0x40FF'u16
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_DESCRIPTORS_INS* = 0x4100'u16
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_DESCRIPTORS_CFM* = 0x4110'u16
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_DESCRIPTORS_EVT* = 0x4111'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_WITHOUT_RESPONSE_INS* = 0x4102'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_WITHOUT_RESPONSE_CFM* = 0x4112'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_WITHOUT_RESPONSE_EVT* = 0x4113'u16
  BTM_D_OPC_BLE_GATT_C_SIGNED_WRITE_WITHOUT_RESPONSE_INS* = 0x4104'u16
  BTM_D_OPC_BLE_GATT_C_SIGNED_WRITE_WITHOUT_RESPONSE_CFM* = 0x4114'u16
  BTM_D_OPC_BLE_GATT_C_SIGNED_WRITE_WITHOUT_RESPONSE_EVT* = 0x4115'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_INS* = 0x4106'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_CFM* = 0x4116'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_EVT* = 0x4117'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_VALUES_INS* = 0x4108'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_VALUES_CFM* = 0x4118'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_VALUES_EVT* = 0x4119'u16
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_PREPARE_WRITE_INS* = 0x410A'u16
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_PREPARE_WRITE_CFM* = 0x411A'u16
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_PREPARE_WRITE_EVT* = 0x411B'u16
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_EXECUTE_WRITE_INS* = 0x410C'u16
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_EXECUTE_WRITE_CFM* = 0x411C'u16
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_EXECUTE_WRITE_EVT* = 0x411D'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_INS* = 0x410E'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_CFM* = 0x411E'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_EVT* = 0x411F'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_DESCRIPTORS_INS* = 0x4120'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_DESCRIPTORS_CFM* = 0x4130'u16
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_DESCRIPTORS_EVT* = 0x4131'u16
  BTM_D_OPC_BLE_GATT_C_HANDLE_VALUE_EVT* = 0x4132'u16

## BLE GATTサーバー機能( GATT_S )
const
  BTM_D_OPC_BLE_GATT_S_ADD_PRIMARY_SERVICE_REQ* = 0x4080'u16
  BTM_D_OPC_BLE_GATT_S_ADD_PRIMARY_SERVICE_RSP* = 0x4090'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_CCCD_REJECT_REQ* = 0x4081'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_CCCD_REJECT_RSP* = 0x4091'u16
  BTM_D_OPC_BLE_GATT_S_ADD_SECONDARY_SERVICE_REQ* = 0x4082'u16
  BTM_D_OPC_BLE_GATT_S_ADD_SECONDARY_SERVICE_RSP* = 0x4092'u16
  BTM_D_OPC_BLE_GATT_S_SERVER_START_REQ* = 0x4084'u16
  BTM_D_OPC_BLE_GATT_S_SERVER_START_RSP* = 0x4094'u16
  BTM_D_OPC_BLE_GATT_S_ADD_CHARACTERISTIC_REQ* = 0x4086'u16
  BTM_D_OPC_BLE_GATT_S_ADD_CHARACTERISTIC_RSP* = 0x4096'u16
  BTM_D_OPC_BLE_GATT_S_ADD_CHARACTERISTIC_DESCRIPTOR_REQ* = 0x4087'u16
  BTM_D_OPC_BLE_GATT_S_ADD_CHARACTERISTIC_DESCRIPTOR_RSP* = 0x4097'u16
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_VALUE_UPDATE_REQ* = 0x408A'u16
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_VALUE_UPDATE_RSP* = 0x409A'u16
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_VALUE_GET_REQ* = 0x408B'u16
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_VALUE_GET_RSP* = 0x409B'u16
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_CONFIRM_UPDATE_REQ* = 0x408C'u16
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_CONFIRM_UPDATE_RSP* = 0x409C'u16
  BTM_D_OPC_BLE_GATT_S_GAP_RECORD_UPDATE_REQ* = 0x408D'u16
  BTM_D_OPC_BLE_GATT_S_GAP_RECORD_UPDATE_RSP* = 0x409D'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_REQUEST_EVT* = 0x409E'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_CONFIRM_EVT* = 0x408F'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_RESULT_EVT* = 0x409F'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_EVT* = 0x4098'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_READ_REQUEST_EVT* = 0x40B5'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_READ_CONFIRM_EVT* = 0x40A5'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_READ_RESULT_EVT* = 0x40B6'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_READ_EVT* = 0x4099'u16
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_NOTIFICATION_INS* = 0x40A1'u16
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_NOTIFICATION_CFM* = 0x40B1'u16
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_NOTIFICATION_EVT* = 0x40B2'u16
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_INDICATION_INS* = 0x40A3'u16
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_INDICATION_CFM* = 0x40B3'u16
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_INDICATION_EVT* = 0x40B4'u16
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_CCC_EVT* = 0x40B7'u16

# GAP 要求 (APP -> BTM)
const OPC_GAP_REQUESTS* = [
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_PARAMETERS_REQ,
  BTM_D_OPC_BLE_GAP_READ_ADVERTISING_CHANNEL_TX_POWER_REQ,
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_DATA_REQ,
  BTM_D_OPC_BLE_GAP_SET_SCAN_RESPONSE_DATA_REQ,
  BTM_D_OPC_BLE_GAP_SET_ADVERTISE_ENABLE_REQ,
  BTM_D_OPC_BLE_GAP_SET_SCAN_PARAMETERS_REQ,
  BTM_D_OPC_BLE_GAP_SET_SCAN_ENABLE_REQ,
  BTM_D_OPC_BLE_GAP_READ_WHITE_LIST_SIZE_REQ,
  BTM_D_OPC_BLE_GAP_CLEAR_WHITE_LIST_REQ,
  BTM_D_OPC_BLE_GAP_ADD_DEVICE_TO_WHITE_LIST_REQ,
  BTM_D_OPC_BLE_GAP_REMOVE_DEVICE_FROM_WHITE_LIST_REQ,
  BTM_D_OPC_BLE_GAP_SET_HOST_CHANNEL_CLASSIFICATION_REQ,
  BTM_D_OPC_BLE_GAP_READ_SUPPORTED_STATES_REQ,
  BTM_D_OPC_BLE_GAP_RSSI_REQ,
  BTM_D_OPC_BLE_GAP_READ_PHY_REQ,
  BTM_D_OPC_BLE_GAP_SET_DEFAULT_PHY_REQ,
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_SET_RANDOM_ADDRESS_REQ,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_PARAMETERS_REQ,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_DATA_REQ,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_RESPONSE_DATA_REQ,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_ENABLE_REQ,
  BTM_D_OPC_BLE_GAP_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_REQ,
  BTM_D_OPC_BLE_GAP_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_REQ,
  BTM_D_OPC_BLE_GAP_REMOVE_ADVERTISING_SET_REQ,
  BTM_D_OPC_BLE_GAP_CLEAR_ADVERTISING_SETS_REQ,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_PARAMETERS_REQ,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_ENABLE_REQ,
  BTM_D_OPC_BLE_GAP_READ_TRASMIT_POWER_REQ,
  BTM_D_OPC_BLE_GAP_READ_RF_PATH_COMPENSATION_REQ,
  BTM_D_OPC_BLE_GAP_WRITE_RF_PATH_COMPENSATION_REQ
]

# GAP 応答 (APP <- BTM)
const OPC_GAP_RESPONSES* = [
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_PARAMETERS_RSP,
  BTM_D_OPC_BLE_GAP_READ_ADVERTISING_CHANNEL_TX_POWER_RSP,
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_DATA_RSP,
  BTM_D_OPC_BLE_GAP_SET_SCAN_RESPONSE_DATA_RSP,
  BTM_D_OPC_BLE_GAP_SET_ADVERTISE_ENABLE_RSP,
  BTM_D_OPC_BLE_GAP_SET_SCAN_PARAMETERS_RSP,
  BTM_D_OPC_BLE_GAP_SET_SCAN_ENABLE_RSP,
  BTM_D_OPC_BLE_GAP_READ_WHITE_LIST_SIZE_RSP,
  BTM_D_OPC_BLE_GAP_CLEAR_WHITE_LIST_RSP,
  BTM_D_OPC_BLE_GAP_ADD_DEVICE_TO_WHITE_LIST_RSP,
  BTM_D_OPC_BLE_GAP_REMOVE_DEVICE_FROM_WHITE_LIST_RSP,
  BTM_D_OPC_BLE_GAP_SET_HOST_CHANNEL_CLASSIFICATION_RSP,
  BTM_D_OPC_BLE_GAP_READ_SUPPORTED_STATES_RSP,
  BTM_D_OPC_BLE_GAP_RSSI_RSP,
  BTM_D_OPC_BLE_GAP_READ_PHY_RSP,
  BTM_D_OPC_BLE_GAP_SET_DEFAULT_PHY_RSP,
  BTM_D_OPC_BLE_GAP_SET_ADVERTISING_SET_RANDOM_ADDRESS_RSP,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_PARAMETERS_RSP,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_DATA_RSP,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_RESPONSE_DATA_RSP,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_ADVERTISING_ENABLE_RSP,
  BTM_D_OPC_BLE_GAP_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_RSP,
  BTM_D_OPC_BLE_GAP_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_RSP,
  BTM_D_OPC_BLE_GAP_REMOVE_ADVERTISING_SET_RSP,
  BTM_D_OPC_BLE_GAP_CLEAR_ADVERTISING_SETS_RSP,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_PARAMETERS_RSP,
  BTM_D_OPC_BLE_GAP_SET_EXTENDED_SCAN_ENABLE_RSP,
  BTM_D_OPC_BLE_GAP_READ_TRASMIT_POWER_RSP,
  BTM_D_OPC_BLE_GAP_READ_RF_PATH_COMPENSATION_RSP,
  BTM_D_OPC_BLE_GAP_WRITE_RF_PATH_COMPENSATION_RSP,
  BTM_D_OPC_MNG_LE_BOOT_COMPLETE_EVT
]

# GAP 指示 (APP -> BTM)
const OPC_GAP_INSTRUCTIONS* = [
  BTM_D_OPC_BLE_GAP_DISCONNECT_INS,
  BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_INS,
  BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_INS,
  BTM_D_OPC_BLE_GAP_SET_PHY_INS
]

# GAP 確認 (APP <- BTM)
const OPC_GAP_CONFIRMATIONS* = [
  BTM_D_OPC_BLE_GAP_DISCONNECT_CFM,
  BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_CFM,
  BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_CFM,
  BTM_D_OPC_BLE_GAP_SET_PHY_CFM
]

# GAP 通知 (APP <- BTM)
const OPC_GAP_EVENTS* = [
  BTM_D_OPC_BLE_GAP_CONNECTION_COMPLETE_EVT,
  BTM_D_OPC_BLE_GAP_DISCONNECTION_COMPLETE_EVT,
  BTM_D_OPC_BLE_GAP_CONNECTION_UPDATE_EVT,
  BTM_D_OPC_BLE_GAP_READ_REMOTE_USED_FEATURES_EVT,
  BTM_D_OPC_BLE_GAP_ENCRYPTION_CHANGE_EVT,
  BTM_D_OPC_BLE_GAP_PHY_UPDATE_COMPLETE_EVT,
  BTM_D_OPC_BLE_GAP_ADVERTISING_SET_TERMINATED_EVT,
  BTM_D_OPC_BLE_GAP_SCAN_REQUEST_RECEIVED_EVT,
  BTM_D_OPC_BLE_GAP_SCAN_TIMEOUT_EVT,
  BTM_D_OPC_BLE_GAP_EXTENDED_ADVERTISING_REPORT_EVT,
  BTM_D_OPC_BLE_GAP_ENHANCED_CONNECTION_COMPLETE_EVT,
  BTM_D_OPC_BLE_GAP_CHANNEL_SELECTION_ALGORITHM_EVT
]

# GAP Advertising (APP <- BTM)
const OPC_GAP_ADVERTISING* = [
  BTM_D_OPC_BLE_GAP_ADVERTISING_REPORT_EVT
]

# SM 要求 (APP -> BTM)
const OPC_SM_REQUESTS* = [
  BTM_D_OPC_BLE_SM_LOCAL_IO_CAPABILITIES_SET_REQ,
  BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_REQ,
  BTM_D_OPC_BLE_SM_DEFAULT_INITIATOR_KEY_DISTRIBUTION_SET_REQ,
  BTM_D_OPC_BLE_SM_LOCAL_DEVICE_KEY_SET_REQ,
  BTM_D_OPC_BLE_SM_REMOTE_COLLECTION_KEY_SET_REQ,
  BTM_D_OPC_BLE_SM_REMOTE_DISTRIBUTION_KEY_SET_REQ,
  BTM_D_OPC_BLE_SM_REMOTE_DEVICE_KEY_DELETE_REQ,
  BTM_D_OPC_BLE_SM_DEFAULT_RESPONDER_KEY_DISTRIBUTION_SET_REQ,
  BTM_D_OPC_BLE_SM_LOCAL_OOB_DATA_CREATE_REQ,
  BTM_D_OPC_BLE_SM_REMOTE_OOB_DATA_SET_REQ,
  BTM_D_OPC_BLE_SM_PRIVATE_ADDRESS_RESOLVE_CHECK_REQ
]

# SM 応答 (APP <- BTM)
const OPC_SM_RESPONSES* = [
  BTM_D_OPC_BLE_SM_LOCAL_IO_CAPABILITIES_SET_RSP,
  BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_RSP,
  BTM_D_OPC_BLE_SM_DEFAULT_INITIATOR_KEY_DISTRIBUTION_SET_RSP,
  BTM_D_OPC_BLE_SM_LOCAL_DEVICE_KEY_SET_RSP,
  BTM_D_OPC_BLE_SM_REMOTE_COLLECTION_KEY_SET_RSP,
  BTM_D_OPC_BLE_SM_REMOTE_DISTRIBUTION_KEY_SET_RSP,
  BTM_D_OPC_BLE_SM_REMOTE_DEVICE_KEY_DELETE_RSP,
  BTM_D_OPC_BLE_SM_DEFAULT_RESPONDER_KEY_DISTRIBUTION_SET_RSP,
  BTM_D_OPC_BLE_SM_LOCAL_OOB_DATA_CREATE_RSP,
  BTM_D_OPC_BLE_SM_REMOTE_OOB_DATA_SET_RSP,
  BTM_D_OPC_BLE_SM_PRIVATE_ADDRESS_RESOLVE_CHECK_RSP
]

# SM 指示 (APP -> BTM)
const OPC_SM_INSTRUCTIONS* = [
  BTM_D_OPC_BLE_SM_PAIRING_INS
]

# SM 確認 (APP <- BTM)
const OPC_SM_CONFIRMATIONS* = [
  BTM_D_OPC_BLE_SM_PAIRING_CFM
]

# SM 通知 (APP <- BTM)
const OPC_SM_EVENTS* = [
  BTM_D_OPC_BLE_SM_USER_CONFIRMATION_REQUEST_EVT,
  BTM_D_OPC_BLE_SM_PASSKEY_REQUEST_EVT,
  BTM_D_OPC_BLE_SM_PASSKEY_DISPLAY_REQUEST_EVT,
  BTM_D_OPC_BLE_SM_LTK_RECEIVE_EVT,
  BTM_D_OPC_BLE_SM_EDIV_RAND_RECEIVE_EVT,
  BTM_D_OPC_BLE_SM_IRK_RECEIVE_EVT,
  BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_RECEIVE_EVT,
  BTM_D_OPC_BLE_SM_CSRK_RECEIVE_EVT,
  BTM_D_OPC_BLE_SM_LTK_SEND_EVT,
  BTM_D_OPC_BLE_SM_EDIV_RAND_SEND_EVT,
  BTM_D_OPC_BLE_SM_IRK_SEND_EVT,
  BTM_D_OPC_BLE_SM_ADDRESS_INFORMATION_SEND_EVT,
  BTM_D_OPC_BLE_SM_CSRK_SEND_EVT,
  BTM_D_OPC_BLE_SM_AUTHENTICATION_COMPLETE_EVT,
  BTM_D_OPC_BLE_SM_AUTHENTICATION_FAILED_EVT,
  BTM_D_OPC_BLE_SM_LOCAL_SECURITY_PROPERTY_EVT
]

# GATT[Common] 指示 (APP -> BTM)
const OPC_GATT_CMN_INSTRUCTIONS* = [
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_INS,
  BTM_D_OPC_BLE_GATT_CMN_EXTENDED_CONNECT_INS,
  BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_INS,
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_CANCEL_INS
]

# GATT[Common] 確認 (APP <- BTM)
const OPC_GATT_CMN_CONFIRMATIONS* = [
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_CFM,
  BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_CFM,
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_CANCEL_CFM
]

# GATT[Common] 通知 (APP <- BTM)
const OPC_GATT_CMN_EVENTS* = [
  BTM_D_OPC_BLE_GATT_CMN_CONNECT_EVT,
  BTM_D_OPC_BLE_GATT_CMN_DISCONNECT_EVT
]

# GATT[Client] 指示 (APP -> BTM)
const OPC_GATT_CLIENT_INSTRUCTIONS* = [
  BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_INS,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_INS,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_PRIMARY_SERVICES_BY_SERVICE_UUID_INS,
  BTM_D_OPC_BLE_GATT_C_FIND_INCLUDED_SERVICES_INS,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_INS,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_INS,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_INS,
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_INS,
  BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_INS,
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_VALUES_INS,
  BTM_D_OPC_BLE_GATT_C_READ_MULTIPLE_CHARACTERISTIC_VALUES_INS,
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_INS,
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_DESCRIPTORS_INS,
  BTM_D_OPC_BLE_GATT_C_WRITE_WITHOUT_RESPONSE_INS,
  BTM_D_OPC_BLE_GATT_C_SIGNED_WRITE_WITHOUT_RESPONSE_INS,
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_INS,
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_VALUES_INS,
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_PREPARE_WRITE_INS,
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_EXECUTE_WRITE_INS,
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_INS,
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_DESCRIPTORS_INS
]

# GATT[Client] 確認 (APP <- BTM)
const OPC_GATT_CLIENT_CONFIRMATIONS* = [
  BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_CFM,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_CFM,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_PRIMARY_SERVICES_BY_SERVICE_UUID_CFM,
  BTM_D_OPC_BLE_GATT_C_FIND_INCLUDED_SERVICES_CFM,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_CFM,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_CFM,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_CFM,
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_CFM,
  BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_CFM,
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_VALUES_CFM,
  BTM_D_OPC_BLE_GATT_C_READ_MULTIPLE_CHARACTERISTIC_VALUES_CFM,
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_CFM,
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_DESCRIPTORS_CFM,
  BTM_D_OPC_BLE_GATT_C_WRITE_WITHOUT_RESPONSE_CFM,
  BTM_D_OPC_BLE_GATT_C_SIGNED_WRITE_WITHOUT_RESPONSE_CFM,
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_CFM,
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_VALUES_CFM,
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_PREPARE_WRITE_CFM,
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_EXECUTE_WRITE_CFM,
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_CFM,
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_DESCRIPTORS_CFM
]

# GATT[Client] 通知 (APP <- BTM)
const OPC_GATT_CLIENT_EVENTS* = [
  BTM_D_OPC_BLE_GATT_C_EXCHANGE_MTU_EVT,
  BTM_D_OPC_BLE_GATT_C_ALL_PRIMARY_SERVICES_EVT,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_PRIMARY_SERVICES_EVT,
  BTM_D_OPC_BLE_GATT_C_PRIMARY_SERVICES_EVT,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_PRIMARY_SERVICES_BY_SERVICE_UUID_EVT,
  BTM_D_OPC_BLE_GATT_C_INCLUDED_SERVICES_EVT,
  BTM_D_OPC_BLE_GATT_C_FIND_INCLUDED_SERVICES_EVT,
  BTM_D_OPC_BLE_GATT_C_ALL_CHARACTERISTICS_OF_A_SERVICE_EVT,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTICS_OF_A_SERVICE_EVT,
  BTM_D_OPC_BLE_GATT_C_CHARACTERISTICS_BY_UUID_EVT,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_CHARACTERISTICS_BY_UUID_EVT,
  BTM_D_OPC_BLE_GATT_C_ALL_CHARACTERISTIC_DESCRIPTORS_EVT,
  BTM_D_OPC_BLE_GATT_C_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_EVT,
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_VALUE_EVT,
  BTM_D_OPC_BLE_GATT_C_READ_USING_CHARACTERISTIC_UUID_EVT,
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_VALUES_EVT,
  BTM_D_OPC_BLE_GATT_C_READ_MULTIPLE_CHARACTERISTIC_VALUES_EVT,
  BTM_D_OPC_BLE_GATT_C_READ_CHARACTERISTIC_DESCRIPTORS_EVT,
  BTM_D_OPC_BLE_GATT_C_READ_LONG_CHARACTERISTIC_DESCRIPTORS_EVT,
  BTM_D_OPC_BLE_GATT_C_WRITE_WITHOUT_RESPONSE_EVT,
  BTM_D_OPC_BLE_GATT_C_SIGNED_WRITE_WITHOUT_RESPONSE_EVT,
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_VALUE_EVT,
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_VALUES_EVT,
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_PREPARE_WRITE_EVT,
  BTM_D_OPC_BLE_GATT_C_RELIABLE_WRITES_EXECUTE_WRITE_EVT,
  BTM_D_OPC_BLE_GATT_C_WRITE_CHARACTERISTIC_DESCRIPTORS_EVT,
  BTM_D_OPC_BLE_GATT_C_WRITE_LONG_CHARACTERISTIC_DESCRIPTORS_EVT
]

# GATT[Client] 通知(Notify) (APP <- BTM)
const OPC_GATT_CLIENT_NOTIFY* = [
  BTM_D_OPC_BLE_GATT_C_HANDLE_VALUE_EVT
]

# GATT[Server] 要求 (APP -> BTM)
const OPC_GATT_S_REQUESTS* = [
  BTM_D_OPC_BLE_GATT_S_ADD_PRIMARY_SERVICE_REQ,
  BTM_D_OPC_BLE_GATT_S_REMOTE_CCCD_REJECT_REQ,
  BTM_D_OPC_BLE_GATT_S_ADD_SECONDARY_SERVICE_REQ,
  BTM_D_OPC_BLE_GATT_S_SERVER_START_REQ,
  BTM_D_OPC_BLE_GATT_S_ADD_CHARACTERISTIC_REQ,
  BTM_D_OPC_BLE_GATT_S_ADD_CHARACTERISTIC_DESCRIPTOR_REQ,
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_VALUE_UPDATE_REQ,
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_VALUE_GET_REQ,
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_CONFIRM_UPDATE_REQ,
  BTM_D_OPC_BLE_GATT_S_GAP_RECORD_UPDATE_REQ
]

# GATT[Server] 応答 (APP <- BTM)
const OPC_GATT_SERVER_RESPONSES* = [
  BTM_D_OPC_BLE_GATT_S_ADD_PRIMARY_SERVICE_RSP,
  BTM_D_OPC_BLE_GATT_S_REMOTE_CCCD_REJECT_RSP,
  BTM_D_OPC_BLE_GATT_S_ADD_SECONDARY_SERVICE_RSP,
  BTM_D_OPC_BLE_GATT_S_SERVER_START_RSP,
  BTM_D_OPC_BLE_GATT_S_ADD_CHARACTERISTIC_RSP,
  BTM_D_OPC_BLE_GATT_S_ADD_CHARACTERISTIC_DESCRIPTOR_RSP,
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_VALUE_UPDATE_RSP,
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_VALUE_GET_RSP,
  BTM_D_OPC_BLE_GATT_S_CHARACTERISTIC_CONFIRM_UPDATE_RSP,
  BTM_D_OPC_BLE_GATT_S_GAP_RECORD_UPDATE_RSP
]

# GATT[Server] 指示 (APP -> BTM)
const OPC_GATT_SERVER_INSTRUCTIONS* = [
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_NOTIFICATION_INS,
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_INDICATION_INS
]

# GATT[Server] 確認 (APP <- BTM)
const OPC_GATT_SERVER_CONFIRMATIONS* = [
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_NOTIFICATION_CFM,
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_INDICATION_CFM
]

# GATT[Server] 通知 (APP <- BTM)
const OPC_GATT_SERVER_EVENTS* = [
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_REQUEST_EVT,
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_CONFIRM_EVT,
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_RESULT_EVT,
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_EVT,
  BTM_D_OPC_BLE_GATT_S_REMOTE_READ_REQUEST_EVT,
  BTM_D_OPC_BLE_GATT_S_REMOTE_READ_CONFIRM_EVT,
  BTM_D_OPC_BLE_GATT_S_REMOTE_READ_RESULT_EVT,
  BTM_D_OPC_BLE_GATT_S_REMOTE_READ_EVT,
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_NOTIFICATION_EVT,
  BTM_D_OPC_BLE_GATT_S_HANDLE_VALUE_INDICATION_EVT,
  BTM_D_OPC_BLE_GATT_S_REMOTE_WRITE_CCC_EVT
]

const OPC_MAIN_RESPONSES* = concat(
  OPC_GAP_RESPONSES.toSeq,
  OPC_GAP_CONFIRMATIONS.toSeq,
  OPC_SM_RESPONSES.toSeq,
  OPC_SM_CONFIRMATIONS.toSeq,
  OPC_GATT_CMN_CONFIRMATIONS.toSeq
)

const OPC_MAIN_EVENTS* = concat(
  OPC_GAP_EVENTS.toSeq,
  OPC_SM_EVENTS.toSeq,
  OPC_GATT_CMN_EVENTS.toSeq
)

type
  OpcCmd* {.pure.} = enum
    # Command (BT APL -> BTM)
    LESecurityModeSettingRequest = BTM_D_OPC_BLE_SM_SECURITY_MODE_SET_REQ
  OpcResp* {.pure.} = enum
    ErroNotification = BTM_D_OPC_MNG_REQ_ERR_EVT
    # Response (BT APL <- BTM)
    LEStartupNotification = BTM_D_OPC_MNG_LE_BOOT_COMPLETE_EVT
