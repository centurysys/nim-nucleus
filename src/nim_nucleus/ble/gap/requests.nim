import ./types

type
  # Set Advertising Parameter Request (0x4000)
  AdvParams* = object
    advIntervalMin*: uint16
    advIntervalMax*: uint16
    case advType*: AdvType
    of AdvType.DIRECT_IND, AdvType.DIRECT_IND_LOW:
      directAddrType*: DirectAddrType
      directAddr*: array[6, uint8]
    else:
      discard
    case ownAddrType*: AddrType
    of AddrType.Public:
      discard
    else:
      randomAddrType*: RandomAddrType
    adcChannelMap*: Channel
    advFilterPolicy*: AdvFilterPolicy

  # Set Scan Paramter Request (0x4005)
  ScanParams* = object
    scanType*: ScanType
    scanInterval*: uint16
    scanWindow*: uint16
    case ownAddrType*: AddrType
    of AddrType.Public:
      discard
    else:
      randomAddrType*: RandomAddrType
    scanningPolicy*: ScanFilterPolicy

  # LE Set Scan Enable Request (0x4006)
  SetScanEnableParams* = object
    scan*: Scan
    filter*: DuplicateFilter