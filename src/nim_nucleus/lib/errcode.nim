type
  ErrorCode* {.pure.} = enum
    Timeouted = (1, "Timeouted")
    Disconnected = (2, "Disconnected")
    Full = (3, "Mailbox Full")
    OpcMismatch = (4, "OPC Mismatch")
    GattError = (5, "GATT Error")
    ParseError = (6, "Parse Error")
    ValueError = (7, "Invalid Value")
