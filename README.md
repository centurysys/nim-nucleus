# nim-nucleus

`nim-nucleus` is a Nim wrapper for the NetNucleus BLE stack.

It provides a small asynchronous BLE Central API for Nim applications, while a
separate bridge daemon, `btmd`, talks to the NetNucleus runtime (`libBTM.so`) on
the target device.

This is not a BlueZ wrapper. It is intended for systems that use the NetNucleus
BLE stack and need a Nim-side API for scanning, connecting, reading/writing GATT
characteristics, receiving notifications, and handling bonding keys.

## Current status

The library is already used in long-running applications, but the public API is
still intentionally small and practical.

The main supported use case is:

- BLE Central role
- scanning and device discovery
- GATT connection management
- characteristic read/write
- descriptor write, including CCC notification/indication setup
- notification wait/receive
- LE security mode and IO capability setup
- remote bonding key collection, export, restore, and removal
- communication with NetNucleus through `btmd`

Peripheral role and a complete high-level BLE abstraction are outside the
current scope.

## Architecture

```text
Nim application
  |
  | import nim_nucleus
  v
BleNim / Gatt high-level API
  |
  v
BleClient
  |
  | Unix domain socket or TCP
  v
btmd
  |
  | libBTM.so / NetNucleus runtime
  v
Bluetooth controller / BLE stack
```

`btmd` is normally run on the target device that has the NetNucleus runtime
installed. Application developers usually do not need to run `btmd` on a normal
development host unless that host also has the NetNucleus runtime.

## Repository layout

```text
nim_nucleus.nimble
src/
  nim_nucleus.nim                  Public high-level API
  app/
    btmd.nim                       NetNucleus bridge daemon
  nim_nucleuspkg/
    ble/
      ble_client.nim               Internal client for btmd protocol handling
      ble_gap.nim                  GAP requests
      ble_gatt_client.nim          GATT client requests/events
      ble_sm.nim                   Security Manager requests/events
      gap/                         GAP parsers, requests, and types
      gatt/                        GATT parsers, requests, and types
      sm/                          SM parsers, requests, and types
      core/                        Common protocol constants and result types
      common/                      Shared protocol parameters and types
    lib/
      asyncsync.nim                Async helpers
      mailbox.nim                  Mailbox/queue helpers
      errcode.nim                  ErrorCode definitions
      syslog.nim                   Logging helpers
```

## Documentation

- [API Guide](docs/api-guide.md)
- [API Guide (Japanese)](docs/api-guide.ja.md)

## Requirements

- Nim 2.2.4 or newer
- NetNucleus BLE runtime on the target device
- `libBTM.so` available to `btmd`

Nim package dependencies are declared in `nim_nucleus.nimble`:

- `results >= 0.5.1`
- `argparse == 0.10.1`
- `pretty >= 0.2.0`

`argparse` is used by the `btmd` executable. Normal library users are mostly
affected by it only when building or running `btmd`.

## Building

For normal Nim application development, import the library from your project as
usual.

```sh
nimble install
```

The package also builds `btmd` from `src/app/btmd.nim` through the nimble setting
`bin = @["app/btmd"]`.

```sh
nimble build
```

`btmd` is mainly intended for target devices that have the NetNucleus runtime
installed.

## Running btmd

By default, the library expects `btmd` to listen on the Unix domain socket:

```text
/tmp/.btmd.sock
```

Example using the default Unix domain socket:

```sh
btmd --path /tmp/.btmd.sock --remove-if-exists
```

Example using TCP:

```sh
btmd --host 127.0.0.1 --port 9876
```

Available options in the current implementation:

```text
-p, --path              Unix domain socket path
-P, --port              TCP listen port
-H, --host              TCP listen host, default: localhost
-r, --remove-if-exists  Remove an existing Unix domain socket before binding
-d, --debug             Enable daemon-side debug output
-l, --logging           Enable logging
-s, --snoop             Enable snoop logging
```

## Basic usage

A minimal application typically creates a `BleNim` instance, initializes it,
scans for a device, connects, and then uses the returned `Gatt` object.

```nim
import std/asyncdispatch
import results
import nim_nucleus

proc main() {.async.} =
  let ble = newBleNim(path = "/tmp/.btmd.sock")

  if not await ble.init():
    echo "failed to initialize BLE stack"
    return

  discard await ble.startStopScan(active = true, enable = true)

  let devRes = await ble.waitDevice(devices = @["MyDevice"], timeout = 10_000)
  if devRes.isErr:
    echo "device not found: ", devRes.error
    return

  let gattRes = await ble.connect(devRes.get())
  if gattRes.isErr:
    echo "connect failed: ", gattRes.error
    return

  let gatt = gattRes.get()
  let batteryRes = await gatt.readGattChar(CharaUuid.BatteryLevel)
  if batteryRes.isOk:
    echo "battery value: ", batteryRes.get().value

  await gatt.disconnect()

waitFor main()
```

The exact scan filter and GATT UUIDs depend on the target device.

## GATT operations

The high-level API is centered around `BleNim` and `Gatt`.

Common operations include:

```nim
let ble = newBleNim()
discard await ble.init()

discard await ble.startStopScan(active = true, enable = true)
let devices = ble.allDevices()
let dev = ble.findDeviceByName("MyDevice")

let gattRes = await ble.connect("AA:BB:CC:DD:EE:FF", random = false)
if gattRes.isOk:
  let gatt = gattRes.get()

  let model = await gatt.readGattChar(CharaUuid.ModelNumber)
  let value = await gatt.readGattChar("2a19")

  discard await gatt.writeGattChar(0x0025'u16, @[0x01'u8, 0x00'u8])
  discard await gatt.writeGattDescriptor(0x0026'u16, CCC.Notify)

  let notifyRes = await gatt.waitNotification(timeout = 10_000)
  await gatt.disconnect()
```

Many high-level operations return `Future[Result[T, ErrorCode]]`. This is useful
for BLE code because timeouts, disconnects, GATT errors, parse errors, and
unexpected protocol responses are normal operational conditions rather than
programming exceptions.

## Bonding keys

`nim-nucleus` can collect remote bonding keys reported by the NetNucleus Security
Manager path and expose them as `RemoteCollectionKeys`.

Typical use:

1. Connect and pair with a device.
2. Wait until encryption/pairing completes if the device requires it.
3. Export remote collection keys from `BleNim`.
4. Persist them in application storage.
5. Restore them on the next application start before reconnecting.

Relevant API:

```nim
let keys = ble.getAllRemoteCollectionKeys()
ble.setAllRemoteCollectionKeys(keys)
discard await ble.removeRemoteCollectionKeys(peer)
discard await ble.removeAllRemoteCollectionKeys()
```

There are also JSON-oriented restore paths through `JsonNode`, which are useful
when applications persist bonding state in a configuration file or local store.

## Error handling

The library uses `results` for many public operations.

Typical pattern:

```nim
let res = await gatt.readGattChar(CharaUuid.BatteryLevel)
if res.isErr:
  echo "read failed: ", res.error
  return

let handleValue = res.get()
```

Common error categories include:

- timeout
- disconnected
- opcode mismatch
- GATT error
- parse error
- invalid value
- device not found

See `src/nim_nucleuspkg/lib/errcode.nim` for the exact `ErrorCode` definition.

## Design notes

- `btmd` isolates the direct NetNucleus / `libBTM.so` integration from normal Nim
  application code.
- `BleClient` handles the internal command/response/event protocol and dispatches
  asynchronous events into dedicated mailboxes.
- `BleNim` provides the application-facing BLE Central API.
- `Gatt` represents an active GATT connection.
- Bonding key handling is part of the high-level API because real devices often
  require reconnecting after pairing and reboot.

## Current limitations and TODO

The code is practical and has been used for long-running processes, but there are
some areas worth improving:

- Add more examples under `examples/`.
- Add parser tests using captured NetNucleus payloads.
- Harden stream socket framing with exact-read helpers.
- Add an explicit shutdown/close API for background tasks and sockets.
- Revisit the `argparse` dependency used by `btmd` and update it if newer
  versions work cleanly.
- Continue keeping the public API small and focused on the BLE Central use case.

## License

MIT
