type
  IoCap* {.pure.} = enum
    DisplayOnly = 0x00'u8
    DisplayYesNo = 0x01'u8
    KeyboardOnly = 0x02'u8
    NoInputNoOutput = 0x03'u8
    KeyboardDisplay = 0x04'u8
  SecurityMode* {.pure.} = enum
    NoAuth = 0x01'u8
    Level2 = 0x02'u8
    Level4 = 0x06'u8
  Irk* = object
    bytes*: array[16, uint8]
  Dhk* = object
    bytes*: array[32, uint8]
