import std/options
import std/strformat
import std/tables
import ../../lib/syslog

type HciStatus* {.pure.} = enum
  BLE_HCI_SUCCESS = 0
  BLE_HCI_ERROR_UNKNOWN_COMMAND = 1
  BLE_HCI_ERROR_NO_CONNECTION = 2
  BLE_HCI_ERROR_HARDWARE_FAILURE = 3
  BLE_HCI_ERROR_PAGE_TIMEOUT = 4
  BLE_HCI_ERROR_AUTHENTICATION_FAILURE = 5
  BLE_HCI_ERROR_KEY_MISSING = 6
  BLE_HCI_ERROR_MEMORY_FULL = 7
  BLE_HCI_ERROR_CONNECTION_TIMEOUT = 8
  BLE_HCI_ERROR_MAX_CONNECTIONS = 9
  BLE_HCI_ERROR_MAX_SCO_CONNECTIONS = 10
  BLE_HCI_ERROR_ACL_ALREADY_EXISTS = 11
  BLE_HCI_ERROR_COMMAND_DISALLOWED = 12
  BLE_HCI_ERROR_LIMITED_RESOURCES = 13
  BLE_HCI_ERROR_SECURITY_RESOURCES = 14
  BLE_HCI_ERROR_UNACCEPTABLE_BD_ADDR = 15
  BLE_HCI_ERROR_HOST_TIMEOUT = 16
  BLE_HCI_ERROR_UNSUPPORTED = 17
  BLE_HCI_ERROR_INVALID_PARAM = 18
  BLE_HCI_ERROR_CONN_TERM_USER = 19
  BLE_HCI_ERROR_CONN_TERM_LRES = 20
  BLE_HCI_ERROR_CONN_TERM_POFF = 21
  BLE_HCI_ERROR_CONN_TERM_LOCAL = 22
  BLE_HCI_ERROR_REPEATED_ATTEMPTS = 23
  BLE_HCI_ERROR_PAIRING = 24
  BLE_HCI_ERROR_UNKNOWN_LMP_PDU = 25
  BLE_HCI_ERROR_UNSUPP_REMOTE_FEAT = 26
  BLE_HCI_ERROR_SCO_OFFSET_REJECT = 27
  BLE_HCI_ERROR_SCO_INTERVAL_REJECT = 28
  BLE_HCI_ERROR_SCO_AIRMODE_REJECT = 29
  BLE_HCI_ERROR_INVALID_LMP_OR_LL_PARAM = 30
  BLE_HCI_ERROR_UNSPECIFIED = 31
  BLE_HCI_ERROR_UNSUPP_LMP_OR_LL_PARAM = 32
  BLE_HCI_ERROR_ROLE_CHANGE_NOT_ALLOW = 33
  BLE_HCI_ERROR_LMP_RES_TIMEOUT = 34
  BLE_HCI_ERROR_LMP_TRANS_COLLISION = 35
  BLE_HCI_ERROR_LMP_PDU_NOT_ALLOW = 36
  BLE_HCI_ERROR_ENCRYPT_NOT_ACCEPT = 37
  BLE_HCI_ERROR_LINKKEY_CANT_CHANGED = 38
  BLE_HCI_ERROR_QOS_NOT_SUPP = 39
  BLE_HCI_ERROR_INSTANT_PASSED = 40
  BLE_HCI_ERROR_PAIRING_UNITKEY_NOT_SUPP = 41
  BLE_HCI_ERROR_DIFFERENT_TRANS_COLLISION = 42
  BLE_HCI_ERROR_RESERVED_43 = 43
  BLE_HCI_ERROR_QOS_UNACCEPTABLE_PARAM = 44
  BLE_HCI_ERROR_QOS_REJECTED = 45
  BLE_HCI_ERROR_CH_CLASS_NOT_SUPP = 46
  BLE_HCI_ERROR_INSUFFICIENT_SECURITY = 47
  BLE_HCI_ERROR_PARAM_OUT_OF_MAND_RANGE = 48
  BLE_HCI_ERROR_RESERVED_49 = 49
  BLE_HCI_ERROR_ROLE_SWITCH_PENDING = 50
  BLE_HCI_ERROR_RESERVED_51 = 51
  BLE_HCI_ERROR_RESERVED_SLOT_VIOLATION = 52
  BLE_HCI_ERROR_ROLE_SWITCH_FAILED = 53
  BLE_HCI_ERROR_EXT_INQ_RES_TOO_LARGE = 54
  BLE_HCI_ERROR_SSP_NOT_SUPPORTED_BY_HOST = 55
  BLE_HCI_ERROR_HOST_BUSY_PAIRING = 56
  BLE_HCI_ERROR_CONN_REJECT_NO_CH_FOUND = 57
  BLE_HCI_ERROR_CONTROLLER_BUSY = 58
  BLE_HCI_ERROR_UNACCEPTABLE_CONN_PARAM = 59
  BLE_HCI_ERROR_ADV_TIMEOUT = 60
  BLE_HCI_ERROR_MIC_FAILURE = 61
  BLE_HCI_ERROR_CONN_FAILED_ESTABLISHED = 62
  BLE_HCI_ERROR_MAC_CONN_FAILED = 63
  BLE_HCI_ERROR_COASE_CLOCK_ADJ_REJECTED = 64
  BLE_HCI_ERROR_TYPE0_SUBMAP_NOT_DEFINED = 65
  BLE_HCI_ERROR_UNKNOWN_ADVERTISING_ID = 66
  BLE_HCI_ERROR_LIMIT_REACHED = 67
  BLE_HCI_ERROR_CANCELLED_BY_HOST = 68

const tblHciStatus = {
  0x00: "Success",
  0x01: "Unknown HCI command",
  0x02: "Unknown Connection Identifier",
  0x03: "Hardware Failure",
  0x04: "Page Timeout",
  0x05: "Authentication Failure",
  0x06: "PIN or Key Missing",
  0x07: "Memory Capacity Exceeded",
  0x08: "Connection Timeout",
  0x09: "Connection Limit Exceeded",
  0x0A: "Synchronous Connection Limit to a Device Exceeded",
  0x0B: "Connection Already Exists",
  0x0C: "Command Disallowed",
  0x0D: "Connection Rejected due to Limited Resources",
  0x0E: "Connection Rejected due to Security Reasons",
  0x0F: "Connection Rejected due to Unacceptable BD_ADDR",
  0x10: "Connection Accept Timeout Exceeded",
  0x11: "Unsupported Feature or Parameter Value",
  0x12: "Invalid HCI Command Parameters",
  0x13: "Remote User Terminated Connection",
  0x14: "Remote Device Terminated Connection due to Low Resources",
  0x15: "Remote Device Terminated Connection due to Power Off",
  0x16: "Connection Terminated by Local Host",
  0x17: "Repeated Attempts",
  0x18: "Pairing not Allowed",
  0x19: "Unknown LMP PDU",
  0x1A: "Unsupported Remote Feature / Unsupported LMP Feature",
  0x1B: "SCO Offset Rejected",
  0x1C: "SCO Interval Rejected",
  0x1D: "SCO Air Mode Rejected",
  0x1E: "Invalid LMP Parameters / Invalid LL Parameters",
  0x1F: "Unspecified Error",
  0x20: "Unsupported LMP Parameter Value / Unsupported LL Parameter Value",
  0x21: "Role Change not Allowed",
  0x22: "LMP Response Timeout / LL Response Timeout",
  0x23: "LMP Error Transaction Collision / LL Procedure Collision",
  0x24: "LMP PDU not Allowed",
  0x25: "Encryption Mode not Acceptable",
  0x26: "Link Key cannot be Changed",
  0x27: "Requested QoS not Supported",
  0x28: "Instant Passed",
  0x29: "Pairing with Unit Key not Supported",
  0x2A: "Different Transaction Collision",
  0x2C: "QoS Unacceptable Parameter",
  0x2D: "QoS Rejected",
  0x2E: "Channel Assessment Not Supported",
  0x2F: "Insufficient Security",
  0x30: "Parameter Out of Mandatory Range",
  0x32: "Role Switch Pending",
  0x34: "Reserved Slot Violation",
  0x35: "Role Switch Failed",
  0x36: "Extended Inquiry Response too Large",
  0x37: "Simple Pairing not Supported by Host",
  0x38: "Host Busy–Pairing",
  0x39: "Connection Rejected due to no Suitable Channel Found",
  0x3A: "Controller Busy",
  0x3B: "Unacceptable Connection Parameters",
  0x3C: "Advertising Timeout",
  0x3D: "Connection Terminated due to MIC Failure",
  0x3E: "Connection Failed to be Established / Synchronization Timeout",
  0x3F: "MAC Connection Failed",
  0x40: "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging",
  0x41: "Type0 Submap not Defined",
  0x42: "Unknown Advertising Identifier",
  0x43: "Limit Reached",
  0x44: "Operation Cancelled by Host"
}.toTable()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc decodeHciStatus*(code: int): Option[HciStatus] =
  try:
    {.warning[HoleEnumConv]:off.}
    let status = HciStatus(code)
    result = some(status)
  except:
    discard

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc strHciStatus*(s: HciStatus|int): string =
  let errStr = tblHciStatus.getOrDefault(s.int)
  if errStr.len > 0:
    result = errStr
  else:
    result = &"Undefined Error: Code 0x{s.int:02x}"

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc checkHciStatus*(code: int, procName: string): bool =
  let hciStatus_opt = code.decodeHciStatus()
  if hciStatus_opt.isNone:
    let errmsg = &"! {procName}: Unknown HciStatus, 0x{code:02x}."
    syslog.error(errmsg)
    return
  let hciStatus = hciStatus_opt.get()
  if hciStatus == HciStatus.BLE_HCI_SUCCESS:
    result = true
  else:
    let errStr = hciStatus.strHciStatus()
    let errmsg = &"! {procName}: failed with status: 0x{code:02x} ({errStr})"
    syslog.error(errmsg)


when isMainModule:
  for errcode in HciStatus.low.int .. HciStatus.high.int + 1:
    let errStr = strHciStatus(errcode)
    echo &"  0x{errcode:02x}: \"{errStr}\","
