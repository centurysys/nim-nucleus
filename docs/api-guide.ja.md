# nim-nucleus API Guide

このドキュメントは、`nim-nucleus` をアプリケーションから使うためのガイドです。

関数ごとの詳細な reference は `nimble doc` で生成される API document を参照してください。このガイドでは、実際の利用手順に重点を置きます。具体的には、BLE 初期化、Advertising report の受信、必要に応じた peripheral への接続、GATT 操作、Notification 受信、bonding key の保存・復旧、終了処理を扱います。

## 1. 概要

`nim-nucleus` は、NetNucleus BLE stack を Nim から扱うための wrapper です。BlueZ wrapper ではありません。NetNucleus を採用した Linux 組み込み機器上で使うことを想定しています。

実行時の構成は、おおむね次のようになります。

```text
Application
  -> BleNim / Gatt
    -> BleClient
      -> btmd
        -> NetNucleus libBTM.so
```

通常のアプリケーションコードでは、次の高レベル API を使います。

- `BleNim`
  - BLE stack 初期化
  - scan
  - device discovery
  - white-list 管理
  - bonding key 管理
  - peripheral への接続
- `Gatt`
  - 接続後の GATT read/write
  - descriptor read/write
  - notification / indication 受信
  - disconnect

`BleClient` と `GattClient` は、より低レベルの構成要素です。内部実装、デバッグ、プロトコルレベルの検証には有用ですが、通常のアプリケーションでは直接使わない方針でよいです。

## 2. API レイヤ構成

| Layer | 主な型 | 対象 |
|---|---|---|
| 高レベル API | `BleNim`, `Gatt`, `BleDevice` | 通常の Nim アプリケーション |
| 内部 BLE client | `BleClient`, `GattClient` | ライブラリ内部、低レベル検証 |
| bridge daemon | `btmd` | 実機への組み込み |
| BLE runtime | NetNucleus `libBTM.so` | vendor stack |

リポジトリ内には `BleClient` を直接扱う開発用・検証用コードが残っている場合があります。これは低レベルの動作確認用です。新規アプリケーションは `BleNim` から使い始めるのが基本です。

## 3. 実行モデル

`btmd` は、NetNucleus runtime が入っている実機上で動かす bridge daemon です。`btmd` は NetNucleus の C API と直接やりとりし、Nim アプリケーションとは socket 経由の framed protocol で通信します。

アプリケーションは Unix domain socket または TCP socket で `btmd` に接続します。

```nim
let ble = newBleNim(path = "/tmp/btmd.sock")
```

または:

```nim
let ble = newBleNim(host = "127.0.0.1", port = 9876)
```

通常、開発 PC 上で `btmd` を動かす必要はありません。`btmd` は NetNucleus runtime が利用できる実機側で動かすものです。

## 4. 基本ライフサイクル

典型的なアプリケーションの流れは次の通りです。

```text
BleNim を作成
BLE を初期化
scan 開始
advertising report を待つ
必要なら対象 device に接続
GATT 操作
scan 停止 / disconnect
BleNim を close
```

最小構成は次のようになります。

```nim
import std/asyncdispatch
import results
import nim_nucleus

proc main() {.async.} =
  let ble = newBleNim()
  if not await ble.init():
    echo "BLE initialization failed"
    return

  try:
    discard await ble.startStopScan(active = true, enable = true)

    let devRes = await ble.waitDevice(timeout = 10_000)
    if devRes.isErr:
      echo "no device found"
      return

    let dev = devRes.get()
    echo dev
  finally:
    discard await ble.startStopScan(active = true, enable = false)
    ble.close()

waitFor main()
```

初期化込みで `BleNim` を作ることもできます。

```nim
let ble = newBleNim(initialize = true)
```

ただし、ある程度大きいアプリケーションでは、`init()` を明示的に呼ぶ方が、初期化成功・失敗を扱いやすくなります。

## 5. Scan と Advertising report

scan の開始・停止には `startStopScan()` を使います。

```nim
discard await ble.startStopScan(
  active = true,
  enable = true,
  filterDuplicates = true,
  filterPolicy = ScanFilterPolicy.AcceptAllExceptDirected
)
```

主な引数は次の通りです。

| 引数 | 意味 |
|---|---|
| `active` | `true` なら Active Scan、`false` なら Passive Scan |
| `enable` | `true` で scan 開始、`false` で scan 停止 |
| `scanInterval` | scan 間隔。0.625 ms 単位。`0` の場合は既存値または default を使う |
| `scanWindow` | 1 回の scan 継続時間。0.625 ms 単位。`0` の場合は既存値または default を使う |
| `filterDuplicates` | duplicate filtering の有効・無効 |
| `filterPolicy` | Advertising packet の受け付け policy |

`waitDevice()` は、受信した advertising report を `BleDevice` として返します。

```nim
let devRes = await ble.waitDevice(timeout = 5_000)
if devRes.isOk:
  let dev = devRes.get()
  echo dev.peerAddrStr
  echo dev.rssi
```

`timeout` の単位は ms です。`timeout = 0` の場合は timeout しません。

`BleDevice` には、アプリケーションでよく使う情報が入ります。

| Field | 意味 |
|---|---|
| `peer` | BLE peer address と address type |
| `peerAddrStr` | `AA:BB:CC:DD:EE:FF` 形式の Bluetooth address 文字列 |
| `name` | advertising data 内の device name。存在しない場合もある |
| `rssi` | RSSI。単位は dBm |
| `advertiseData` | parser が扱った raw advertising payload |
| `manufacturerData` | manufacturer specific data。存在しない場合もある |
| `seenTime` | report を受信した時刻 |

既に見つけた device は次の API で取得できます。

```nim
let devices = ble.allDevices()
let byName = ble.findDeviceByName("MyDevice")
let byAddr = ble.findDeviceByAddr("AA:BB:CC:DD:EE:FF")
```

## 6. Advertising 受信だけのアプリケーション

BLE 機器の中には、GATT 接続をしなくても advertising packet だけで必要な情報を取得できるものがあります。センサー、ビーコン、簡易的な状態通知を行う機器では、この構成が多くあります。

この用途では、典型的には次の構成になります。

1. Active Scan または Passive Scan を開始する。
2. 一定時間 `waitDevice()` を繰り返す。
3. `manufacturerData`、service UUID、name などを読む。
4. `peerAddrStr` を key にした table に状態を保存する。
5. 同じ address から届く複数 report を統合する。

骨格は次のようになります。

```nim
import std/asyncdispatch
import std/options
import std/tables
import std/times
import nim_nucleus

type
  FoundDevice = object
    address: string
    name: Option[string]
    rssi: int8

proc collectAdvertising(ble: BleNim, durationSec: int): Future[Table[string, FoundDevice]] {.async.} =
  var devices: Table[string, FoundDevice]
  let endTime = now().toTime.toUnixFloat() + durationSec.float

  while true:
    let waitMs = int((endTime - now().toTime.toUnixFloat()) * 1000.0)
    if waitMs <= 0:
      break

    let devRes = await ble.waitDevice(timeout = waitMs)
    if devRes.isErr:
      break

    let dev = devRes.get()
    devices[dev.peerAddrStr] = FoundDevice(
      address: dev.peerAddrStr,
      name: dev.name,
      rssi: dev.rssi
    )

  result = devices
```

Advertising 受信だけのアプリケーションでは、1 回の report に必要な情報がすべて入っているとは限りません。機器によっては advertising packet に manufacturer data、scan response に device type や service 情報が入ることがあります。

そのため、`peerAddrStr` を key にした小さな table を持ち、同じ address から来た複数 report をまとめて扱う構成が実用的です。

SwitchBot 風の parser であれば、たとえば次のように manufacturer data を見ます。

```nim
if dev.manufacturerData.isSome:
  let manData = dev.manufacturerData.get()
  if manData.len >= 2:
    let companyId = manData.getLe16(0)
    if companyId == 0x0969'u16:
      echo "SwitchBot-family device candidate: ", dev.peerAddrStr
```

その後、同じ address から届く scan response を使って device type を確定する、という流れになります。

## 7. 検出後に GATT 接続する

GATT 接続には `connect()` を使います。

```nim
let gattRes = await ble.connect(dev, timeout = 10_000)
if gattRes.isErr:
  echo "connect failed: ", gattRes.error
  return

let gatt = gattRes.get()
```

Bluetooth address 文字列で接続することもできます。

```nim
let gattRes = await ble.connect("AA:BB:CC:DD:EE:FF", random = false)
```

scan 中に接続する場合、`connect()` はいったん scan を停止してから GATT 接続を開始します。NetNucleus/controller の組み合わせによっては、Central として接続開始中かつ scan 中という状態をサポートしないためです。

接続後に scan を再開したい場合は `autoRescan = true` を指定します。

```nim
let gattRes = await ble.connect(dev, autoRescan = true, timeout = 10_000)
```

多数の device を scan し、条件に合うものだけ GATT 接続するアプリケーションでは、GATT 接続ごとに async task を起動する構成が扱いやすいです。

```nim
proc handleGatt(gatt: Gatt) {.async.} =
  try:
    let nameRes = await gatt.readGattChar(CharaUuid.DeviceName)
    if nameRes.isOk:
      echo nameRes.get().value.toString()
  finally:
    await gatt.disconnect()

let gattRes = await ble.connect(dev, timeout = 10_000)
if gattRes.isOk:
  asyncCheck handleGatt(gattRes.get())
  discard await ble.restartScan()
```

## 8. GATT の基本操作

`connect()` が成功すると、`Gatt` object が返ります。以降の GATT 操作はこの `Gatt` に対して行います。

### UUID で characteristic を読む

```nim
let nameRes = await gatt.readGattChar(CharaUuid.DeviceName)
if nameRes.isOk:
  let hv = nameRes.get()
  echo hv.value.toString()
```

UUID 文字列を直接指定することもできます。

```nim
let battRes = await gatt.readGattChar("2a19")
```

### handle で characteristic を読む

```nim
let valueRes = await gatt.readGattChar(0x0021'u16)
if valueRes.isOk:
  let bytes = valueRes.get()
```

### handle で characteristic に書く

```nim
discard await gatt.writeGattChar(0x0024'u16, @[0x01'u8])
```

Write Without Response を使う場合は、`withResponse = false` を指定します。

```nim
discard await gatt.writeGattChar(0x0024'u16, @[0x01'u8], withResponse = false)
```

### descriptor の read/write

```nim
let descRes = await gatt.readGattDescriptor(0x0022'u16)
discard await gatt.writeGattDescriptor(0x0022'u16, 0x0001'u16)
```

CCCD 操作では、可能であれば `CCC` enum を使います。

```nim
discard await gatt.writeGattDescriptor(0x0022'u16, CCC.Notify)
```

## 9. Notification と CCCD

BLE の notification / indication は、通常 CCCD、つまり Client Characteristic Configuration Descriptor に値を書いて有効化します。

代表的な値は次の通りです。

| 値 | `CCC` enum | 意味 |
|---:|---|---|
| `0x0000` | `CCC.Disable` | notification / indication を無効化 |
| `0x0001` | `CCC.Notify` | notification を有効化 |
| `0x0002` | `CCC.Indicate` | indication を有効化 |

例:

```nim
const valueHandle = 0x0021'u16
const cccdHandle = 0x0022'u16

discard await gatt.writeGattDescriptor(cccdHandle, CCC.Notify)

try:
  while gatt.isConnected():
    let notifyRes = await gatt.waitNotification(timeout = 10_000)
    if notifyRes.isErr:
      break

    let hv = notifyRes.get()
    if hv.handle == valueHandle:
      echo hv.value
finally:
  discard await gatt.writeGattDescriptor(cccdHandle, CCC.Disable)
```

実際の value handle と CCCD handle は、service/characteristic discovery の結果、または機器仕様から決めます。

## 10. Bonding key

Peripheral によっては pairing / bonding が必要です。Central として動作するアプリケーションでは、再起動後も同じ peripheral と接続できるようにするため、remote device key をアプリ側で永続化する必要があります。

主な型は `RemoteCollectionKeys` です。

基本的な流れは次の通りです。

1. 起動時に保存済み key を読み込む。
2. 接続前に `setAllRemoteCollectionKeys()` で NetNucleus 側に key を登録する。
3. Peripheral と接続・pairing する。
4. pairing 完了後に `getAllRemoteCollectionKeys()` で key を取得する。
5. 取得した key をファイルなどに保存する。

起動時に key を復旧する例:

```nim
import std/json

let jsonNode = parseFile("bonded-keys.json")
discard await ble.setAllRemoteCollectionKeys(jsonNode)
```

key を保存する例:

```nim
let keys = ble.getAllRemoteCollectionKeys()
writeFile("bonded-keys.json", $(%keys))
```

特定 peripheral の key を削除する例:

```nim
discard await ble.removeRemoteCollectionKeys(peer)
```

すべての保存 key を削除する例:

```nim
discard await ble.removeAllRemoteCollectionKeys()
```

接続直後に peripheral 側から暗号化や pairing が開始される機器では、暗号化完了を待ってから GATT 操作を行います。

```nim
let encRes = await gatt.waitEncryptionComplete()
if encRes.isErr:
  echo "encryption did not complete: ", encRes.error
```

## 11. White-list 管理

`BleNim` は、controller / stack 側の white list 管理 API も提供します。

```nim
let size = await ble.getWhiteListSize()
discard await ble.clearWhiteList()
discard await ble.addDeviceToWhiteList("AA:BB:CC:DD:EE:FF")
discard await ble.removeDeviceFromWhiteList("AA:BB:CC:DD:EE:FF")
```

現在の in-memory white list は次のように列挙できます。

```nim
for peer in ble.devicesInWhiteList():
  echo peer
```

white list に登録された device だけを scan 対象にしたい場合は、`ScanFilterPolicy.WhitelistOnly` を使います。

## 12. エラー処理

高レベル GATT API の多くは `Future[Result[T, ErrorCode]]` を返します。値を使う前に `isOk` / `isErr` を確認します。

```nim
let res = await gatt.readGattChar(CharaUuid.DeviceName)
if res.isErr:
  case res.error
  of ErrorCode.Timeouted:
    echo "timeout"
  of ErrorCode.Disconnected:
    echo "disconnected"
  else:
    echo "GATT read failed: ", res.error
  return

let value = res.get()
```

代表的な `ErrorCode` の意味は次の通りです。

| ErrorCode | 典型的な意味 | 呼び出し側の対応 |
|---|---|---|
| `Timeouted` | 期待した response / event が時間内に来なかった | retry または reconnect |
| `Disconnected` | peripheral または `btmd` との接続が切れた | reconnect |
| `OpcMismatch` | 期待と異なる opcode を受信した | protocol state の破綻として扱い、再接続を検討 |
| `GattError` | GATT レベルの失敗 | 対象 handle / UUID や device 状態を確認 |
| `ParseError` | packet parse に失敗 | log を残し、必要なら再接続 |
| `ValueError` | 引数または状態が不正 | 呼び出し側の入力・状態管理を修正 |
| `DeviceNotFound` | 対象 device が見つからなかった | scan 継続、filter 条件を確認 |

GAP/setup 系 API の一部は `Result` ではなく `bool` を返します。`false` は失敗として扱い、アプリケーション側で十分な context を log に残してください。

## 13. 非同期処理と並行実行モデル

`nim-nucleus` は `asyncdispatch` ベースです。

典型的には、次の処理が並行して動きます。

- `waitDevice()` による advertising 受信 loop
- 条件に合った device ごとの GATT task
- `waitNotification()` による notification 受信 loop
- `BleNim` / `BleClient` 内部の background handler

推奨する扱いは次の通りです。

- active な GATT 接続ごとに 1 task を割り当てる。
- GATT task 終了時には `disconnect()` する。
- device が明示的な cleanup を期待する場合は、disconnect 前に CCCD を disable する。
- 接続後も scan を続けたい場合は、`autoRescan = true` または `restartScan()` を使う。
- アプリケーション終了時には `BleNim.close()` を呼ぶ。

## 14. 低レベル API について

`BleClient` と `GattClient` は内部 package から利用できますが、基本的には低レベル API と考えてください。NetNucleus の command / event に近い形の API です。

古い開発用 `app.nim` 形式のコードは、内部の command flow を理解するには有用です。ただし、新規アプリケーションでは高レベル API を使う方針でよいです。

| 低レベル形式 | 高レベル形式 |
|---|---|
| `newBleClient()` | `newBleNim()` |
| `initBTM()` | `BleNim.init()` |
| `setScanParametersReq()` + `setScanEnableReq()` | `startStopScan()` |
| 手動 advertising handling | `waitDevice()`, `allDevices()` |
| `gattConnect()` | `BleNim.connect()` |
| `GattClient.gattReadCharacteristicValue()` | `Gatt.readGattChar(handle)` |
| `GattClient.gattReadUsingCharacteristicUuid()` | `Gatt.readGattChar(uuid)` |
| `GattClient.gattWriteCharacteristicDescriptors()` | `Gatt.writeGattDescriptor()` |
| `GattClient.waitNotify()` | `Gatt.waitNotification()` |

NetNucleus protocol 自体の検証や低レベルデバッグが必要な場合を除き、通常は `BleNim` / `Gatt` を使います。

## 15. 実用例

### Advertising collector

```nim
proc scanForSeconds(ble: BleNim, seconds: int) {.async.} =
  discard await ble.startStopScan(active = true, enable = true)
  defer:
    asyncCheck ble.startStopScan(active = true, enable = false)

  let endTime = now().toTime.toUnixFloat() + seconds.float
  while true:
    let waitMs = int((endTime - now().toTime.toUnixFloat()) * 1000.0)
    if waitMs <= 0:
      break

    let devRes = await ble.waitDevice(timeout = waitMs)
    if devRes.isErr:
      break

    let dev = devRes.get()
    echo dev.peerAddrStr, " RSSI=", dev.rssi
```

### 検出した device の Device Name を読む

```nim
let devRes = await ble.waitDevice(timeout = 10_000)
if devRes.isOk:
  let gattRes = await ble.connect(devRes.get(), timeout = 10_000)
  if gattRes.isOk:
    let gatt = gattRes.get()
    try:
      let nameRes = await gatt.readGattChar(CharaUuid.DeviceName)
      if nameRes.isOk:
        echo nameRes.get().value.toString()
    finally:
      await gatt.disconnect()
```

### Notification を有効化する

```nim
const valueHandle = 0x0021'u16
const cccdHandle = 0x0022'u16

discard await gatt.writeGattDescriptor(cccdHandle, CCC.Notify)
let notifyRes = await gatt.waitNotification(timeout = 5_000)
if notifyRes.isOk:
  let hv = notifyRes.get()
  echo "handle=", hv.handle, " value=", hv.value
discard await gatt.writeGattDescriptor(cccdHandle, CCC.Disable)
```
