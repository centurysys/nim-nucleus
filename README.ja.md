# nim-nucleus

`nim-nucleus` は、NetNucleus BLE stack を Nim から扱うための wrapper です。

Nim アプリケーションには小さな非同期 BLE Central API を提供し、NetNucleus
runtime (`libBTM.so`) との直接のやりとりは bridge daemon である `btmd` に分離しています。

これは BlueZ wrapper ではありません。NetNucleus BLE stack を使う機器上で、
Nim から scan、connect、GATT read/write、notification 受信、bonding key 管理を行うためのライブラリです。

## 現状

このライブラリは、すでに長時間動作するアプリケーションで使われています。  
ただし、公開 API は意図的に小さく、実用上必要な範囲に絞っています。

主な対象は次の用途です。

- BLE Central role
- scan / device discovery
- GATT 接続管理
- characteristic read/write
- descriptor write、特に CCC による notification / indication 設定
- notification の待機・受信
- LE security mode / IO capability 設定
- remote bonding key の収集、export、restore、削除
- `btmd` 経由での NetNucleus との通信

Peripheral role や、BLE 全体を広く覆う汎用 high-level abstraction は現時点の対象外です。

## アーキテクチャ

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

`btmd` は通常、NetNucleus runtime が入っている実機側で動かします。
通常の開発 PC 上で `btmd` を動かす必要はありません。開発 PC 側に NetNucleus runtime が入っている場合だけ、`btmd` を直接起動して動作確認できます。

## リポジトリ構成

```text
nim_nucleus.nimble
src/
  nim_nucleus.nim                  公開 high-level API
  app/
    btmd.nim                       NetNucleus bridge daemon
  nim_nucleuspkg/
    ble/
      ble_client.nim               btmd protocol を扱う内部 client
      ble_gap.nim                  GAP request
      ble_gatt_client.nim          GATT client request/event
      ble_sm.nim                   Security Manager request/event
      gap/                         GAP parser / request / type
      gatt/                        GATT parser / request / type
      sm/                          SM parser / request / type
      core/                        protocol constant / result type
      common/                      共通 protocol parameter / type
    lib/
      asyncsync.nim                async helper
      mailbox.nim                  mailbox / queue helper
      errcode.nim                  ErrorCode 定義
      syslog.nim                   logging helper
```

## ドキュメント

- [API Guide](docs/api-guide.md)
- [API Guide 日本語版](docs/api-guide.ja.md)

## 必要なもの

- Nim 2.2.4 以上
- 実機側の NetNucleus BLE runtime
- `btmd` から利用できる `libBTM.so`

Nim package の依存関係は `nim_nucleus.nimble` に記述しています。

- `results >= 0.5.1`
- `argparse == 0.10.1`
- `pretty >= 0.2.0`

`argparse` は `btmd` 実行ファイル用です。通常のライブラリ利用では、主に `btmd` をビルド・実行する場合にだけ関係します。

## ビルド

通常の Nim アプリケーション開発では、プロジェクト側からライブラリとして import して使います。

```sh
nimble install
```

この package は `.nimble` ファイルの `bin = @["app/btmd"]` により、`src/app/btmd.nim` から `btmd` もビルドします。

```sh
nimble build
```

`btmd` は主に NetNucleus runtime が入っている実機側で使う daemon です。

## btmd の起動

デフォルトでは、ライブラリは `btmd` が次の Unix domain socket で listen していることを想定します。

```text
/tmp/.btmd.sock
```

Unix domain socket を使う例です。

```sh
btmd --path /tmp/.btmd.sock --remove-if-exists
```

TCP を使う例です。

```sh
btmd --host 127.0.0.1 --port 9876
```

現在の実装で利用できる option は次のとおりです。

```text
-p, --path              Unix domain socket path
-P, --port              TCP listen port
-H, --host              TCP listen host, default: localhost
-r, --remove-if-exists  既存の Unix domain socket を削除してから bind する
-d, --debug             daemon 側 debug output を有効化
-l, --logging           logging を有効化
-s, --snoop             snoop logging を有効化
```

## 基本的な使い方

典型的なアプリケーションでは、`BleNim` を作成して初期化し、scan、device 発見、connect を行い、返された `Gatt` object を使って GATT 操作を行います。

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

scan filter や GATT UUID は対象 device に合わせて変更してください。

## GATT 操作

High-level API は `BleNim` と `Gatt` を中心にしています。

代表的な操作例です。

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

多くの high-level operation は `Future[Result[T, ErrorCode]]` を返します。  
BLE では timeout、disconnect、GATT error、parse error、想定外の protocol response が通常の運用条件として発生するため、例外ではなく `Result` として扱う設計にしています。

## Bonding key

`nim-nucleus` は、NetNucleus Security Manager 経由で通知される remote bonding key を収集し、`RemoteCollectionKeys` として扱えます。

典型的な流れは次のとおりです。

1. device に接続して pairing する
2. 必要であれば encryption / pairing 完了を待つ
3. `BleNim` から remote collection keys を export する
4. アプリケーション側の保存領域に永続化する
5. 次回起動時に保存した key を restore してから再接続する

関連 API です。

```nim
let keys = ble.getAllRemoteCollectionKeys()
ble.setAllRemoteCollectionKeys(keys)
discard await ble.removeRemoteCollectionKeys(peer)
discard await ble.removeAllRemoteCollectionKeys()
```

`JsonNode` を使った restore path もあります。bonding state を設定ファイルや local store に保存する用途で使えます。

## エラー処理

多くの公開 API は `results` を使います。

典型的な処理パターンです。

```nim
let res = await gatt.readGattChar(CharaUuid.BatteryLevel)
if res.isErr:
  echo "read failed: ", res.error
  return

let handleValue = res.get()
```

主な error category は次のとおりです。

- timeout
- disconnected
- opcode mismatch
- GATT error
- parse error
- invalid value
- device not found

正確な `ErrorCode` 定義は `src/nim_nucleuspkg/lib/errcode.nim` を参照してください。

## 設計メモ

- `btmd` は NetNucleus / `libBTM.so` との直接連携を通常の Nim アプリケーションコードから分離します。
- `BleClient` は内部 command/response/event protocol を処理し、非同期 event を用途別 mailbox に振り分けます。
- `BleNim` はアプリケーション向けの BLE Central API です。
- `Gatt` は active な GATT connection を表します。
- 実機では pairing 後の再接続や reboot 後の復旧が必要になるため、bonding key handling を high-level API に含めています。

## 現在の制限と TODO

実用上は長時間動作するコードとして使えていますが、改善余地はあります。

- `examples/` 以下に利用例を追加する
- captured NetNucleus payload を使った parser test を追加する
- stream socket framing を exact-read helper で堅牢化する
- background task と socket の明示的な shutdown / close API を追加する
- `btmd` が使っている `argparse` 依存を見直し、新しい version で問題なく動くなら更新する
- BLE Central 用途を中心に、公開 API を小さく保つ

## License

MIT
