type SmReason* {.pure.} = enum
  BLE_SM_REASON_PASSKEY_ENTRY_FAILED = (0x01,
    "The user input of passkey failed")
  BLE_SM_REASON_OOB_NOT_AVAILABLE = (0x02,
    "The OOB data is not available")
  BLE_SM_REASON_AUTHENTICATION_REQUIREMENTS = (0x03,
    "Authentication requirements cannot be met due to IOcapabilities of one or both devices")
  BLE_SM_REASON_CONFIRM_VALUE_FAILED = (0x04,
    "The confirm value does not match the calculated compare value")
  BLE_SM_REASON_PAIRING_NOT_SUPPORTED = (0x05, "Pairing is not supported by the device")
  BLE_SM_REASON_ENCRYPTION_KEY_SIZE = (0x06,
    "The resultant encryption key size is insufficient")
  BLE_SM_REASON_COMMAND_NOT_SUPPORTED = (0x07,
    "The SMP command received is not supported on this device")
  BLE_SM_REASON_UNSPECIFIED_REASON = (0x08,
    "Pairing failed due to an unspecified reason")
  BLE_SM_REASON_REPEATED_ATTEMPTS = (0x09,
    "Pairing or authentication procedure is disallowed because too little time has elapsed" &
    " since last pairing request or security request")
  BLE_SM_REASON_INVALID_PARAMETERS = (0x0A, "The Invalid Parameters error code indicates that" &
    " the command length is invalid or that a parameter is outside of the specified range.")
  BLE_SM_REASON_DHKEY_CHECK_FAILED = (0x0B, "Indicates to the remote device that the DHKey" &
    " Check value received doesn’t match the one calculated by the local device.")
  BLE_SM_REASON_NUMERIC_COMPARISON_FAILED = (0x0C, "Indicates that the confirm values in" &
    " the numeric comparison protocol do not match.")
  BLE_SM_REASON_BREDR_PAIRING_IN_PROGRESS = (0x0D, "Indicates that the pairing over the LE" &
    " transport failed due to a Pairing Request sent over the BR/EDR transport in progress.")
  BLE_SM_REASON_CROSS_TRANSPORT_KEY_DERIIVATION_GENERATION_NOT_ALLOWED = (0x0E,
    "Indicates that the BR/EDR Link Key generated on the BR/EDR transport cannot be used" &
    " to derive and distribute keys for the LE transport or the LE LTK generated on the" &
    " LE transport cannot be used to derive a key for the BR/EDR transport.")
  BLE_SM_REASON_KEY_REJECTED = (0x0F,
    "Indicates that the device chose not to accept a distributed key.")
