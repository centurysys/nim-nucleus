type
  # Set Advertising Parameter Request (0x4000)
  AdvType* {.pure.} = enum
    IND = 0x00'u8
    DIRECT_IND = 0x01'u8
    SCAN_IND = 0x02'u8
    NONCONN_IND = 0x03'u8
    DIRECT_IND_LOW = 0x04'u8
  AddrType* {.pure.} = enum
    Public = 0x00'u8
    RandomNonResolvPrivate = 0x01'u8
    RandomResolvPrivate = 0x41'u8
    RandomStatic = 0xc1'u8
  RandomAddrType* {.pure.} = enum
    NonResolvPrivate = 0x00'u8
    ResolvPrivate = 0x40'u8
    Static = 0xc0'u8
  DirectAddrType* {.pure.} = enum
    Public = 0x00'u8
    Random = 0x01'u8
  Channel* = enum
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
  DuplicacaFilter* {.pure.} = enum
    Disable = 0x00'u8
    Enable = 0x01'u8
