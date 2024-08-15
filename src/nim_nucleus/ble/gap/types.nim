import std/options
import ../core/hci_status
import ../common/common_types
export common_types

type
  # Set Advertising Parameter Request (0x4000)
  AdvType* {.pure.} = enum
    IND = 0x00'u8
    DIRECT_IND = 0x01'u8
    SCAN_IND = 0x02'u8
    NONCONN_IND = 0x03'u8
    DIRECT_IND_LOW = 0x04'u8
  AddrTypeEx* {.pure.} = enum
    Public = 0x00'u8
    RandomNonResolvPrivate = 0x01'u8
    RandomResolvPrivate = 0x41'u8
    RandomStatic = 0xc1'u8
  RandomAddrType* {.pure.} = enum
    NonResolvPrivate = 0x00'u8
    ResolvPrivate = 0x40'u8
    Static = 0xc0'u8
  BleChannel* = enum
    ch37 = 0x01'u8
    ch38 = 0x02'u8
    ch39 = 0x04'u8
    chAll = 0x07'u8
  AdvFilterPolicy* {.pure.} = enum
    All = 0x00'u8
    ConnAllScanWhite = 0x01'u8
    ConnWhiteScanAll = 0x02'u8
    WhiteOnly = 0x03'u8

  # Set Scan Paramter Request (0x4005)
  ScanType* {.pure.} = enum
    Passive = 0x00'u8
    Active = 0x01'u8
  ScanFilterPolicy* {.pure.} = enum
    AcceptAllExceptDirected = 0x00'u8
    WhitelistOnly = 0x01'u8
    AcceptAllExceptNotDirected = 0x02'u8
    AcceptAllExceptWhitelistAndNotDirected = 0x03'u8

  # LE Set Scan Enable Request (0x4006)
  Scan* {.pure.} = enum
    Disable = 0x00'u8
    Enable = 0x01'u8
  DuplicateFilter* {.pure.} = enum
    Disable = 0x00'u8
    Enable = 0x01'u8

type
  EventType* {.pure.} = enum
    IND = 0x00
    DIRECT_IND = 0x01
    SCAN_IND = 0x02
    NONCONN_IND = 0x03
    SCAN_RSP = 0x04
  Role* {.pure.} = enum
    Central = 0x00'u8
    Peripheral = 0x01'u8
  ClockAccuracy* = enum
    acc500ppm = (0x00'u8, "500ppm")
    acc250ppm = (0x01'u8, "250ppm")
    acc150ppm = (0x02'u8, "150ppm")
    acc100ppm = (0x03'u8, "100ppm")
    acc75ppm = (0x04'u8, "75ppm")
    acc50ppm = (0x05'u8, "50ppm")
    acc30ppm = (0x06'u8, "30ppm")
    acc25ppm = (0x07'u8, "25ppm")
  ChannSelAlgorithm* {.pure.} = enum
    alg0 = (0x00'u8, "LE Channel Selection Algorithm #1")
    alg1 = (0x01'u8, "LE Channel Selection Algorithm #2")
  # LE Advertising Report (0x4017)
  AdvertisingReport* = object
    eventType*: EventType
    addrType*: AddrType
    bdAddr*: uint64
    name*: Option[string]
    data*: string
    rssi*: int8
  # LE Enhanced Connection Complete 通知 (0x419f)
  EnhConnectionCompleteEvent* = object
    hciStatus*: HciStatus
    conHandle*: uint16
    role*: Role
    peerAddrType*: AddrType
    peerAddr*: uint64
    localPrivateAddr*: uint64
    remotePrivateAddr*: uint64
    conInterval*: uint16
    conLatency*: uint16
    supervisionTImeout*: uint16
    masterClockAccuracy*: ClockAccuracy
  # LE Enhanced Connection Complete 通知 (0x419f)
  ChannelSelAlgorithmReport* = object
    conHandle*: uint16
    alg*: ChannSelAlgorithm
