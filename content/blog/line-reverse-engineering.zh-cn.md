+++
title = "逆向分析 LINE 的 QR 登录协议"
date = 2026-06-02
description = "深入技术分析 LINE 的 QR 码认证协议 — Thrift TCompact 线格式、Curve25519 E2EE 密钥交换与七阶段登录握手流程。"
[taxonomies]
tags = ["reverse-engineering", "line", "thrift", "cryptography", "android"]
+++

## 概述

LINE 的桌面端认证采用七阶段 QR 码握手流程，基于自定义的 Thrift TCompact 二进制协议。本文基于 Android APK 的静态分析（使用 jadx 反编译）和抓包验证，记录了协议的内部细节。

核心组件：

| 反编译类名 | 职责 |
|---|---|
| `rz2/t.java` | QR 登录 ViewModel — 七阶段状态机 |
| `zz2/p.java` | `SecondaryQrCodeLoginServiceClient` — 普通请求的 Thrift RPC 客户端 |
| `zz2/k.java` | 长轮询 RPC 客户端 |
| `tz2/j.java` | Repository — API 方法编排 |
| `q94/c.java` | Curve25519 密钥对生成 + AES/SHA-256 加密原语 |
| `ek1/*.java` | Thrift 生成的请求/响应类型 |

## API 端点

两个独立的服务端点，均位于 `legy-jp.line-apps.com`：

```
普通请求:   POST https://legy-jp.line-apps.com/acct/lgn/sq/v1
长轮询:     POST https://legy-jp.line-apps.com/acct/lp/lgn/sq/v1
```

`zz2/p` 客户端处理普通的请求-响应调用，`zz2/k` 客户端处理长轮询调用（`checkQrCodeVerified`、`checkPinCodeVerified`）。两者使用相同的 Thrift 序列化，但在 HTTP 超时处理上有所不同。

## 必需请求头

```
Content-Type: application/x-thrift; protocol=TCOMPACT
User-Agent: Line/8.7.0
X-Line-Application: DESKTOPMAC\t8.7.0\tMAC\t10.15.7
x-lal: ja_JP
x-lhm: POST
```

认证请求额外需要：
```
X-Line-Access: <accessToken 或 sessionId>
```

长轮询请求额外需要：
```
x-lst: 150000
```

`X-Line-Application` 的格式为 `PLATFORM\tVERSION\tOS\tOS_VERSION`，使用**制表符**（`0x09`）分隔。`x-lst` 头指定长轮询超时时间（毫秒）——服务器会保持 TCP 连接直到超时。

## Thrift TCompact 线协议

LINE 使用 Apache Thrift 的 TCompact 协议，而非 TBinary。由于采用了 delta 编码的字段 ID 和 zigzag 编码的整数，该协议的空间效率显著更高。

### 消息帧格式

```
+----------+----------+--------+-----------+
| 协议 ID  | 版本/类型 | 序列号  | 方法名    |
| 0x82     | 1 字节    | varint | string    |
+----------+----------+--------+-----------+
```

**协议 ID**：固定为 `0x82`。

**版本/类型字节**：`(message_type << 5) | version`
- 第 7-5 位：消息类型（1=CALL, 2=REPLY, 3=EXCEPTION, 4=ONEWAY）
- 第 4-0 位：版本号（固定为 1）

**序列号**：zigzag 编码的 i32，varint 序列化。

**方法名**：长度前缀的 UTF-8 字符串（varint 长度 + 字节内容）。

### 字段头编码

结构体中的每个字段以一个头字节开始：

```
短格式: (delta << 4) | field_type    [1 字节, 当 1 ≤ delta ≤ 15]
长格式: (0x00 | field_type) + i16    [3 字节, 当 delta = 0 或 > 15]
```

`delta` = `当前字段 ID - 上一字段 ID`。上一字段 ID 在每个结构体内跟踪，在 `STRUCT_BEGIN` 时重置为 0。

### 类型常量

| 代码 | 类型 | 编码方式 |
|------|------|----------|
| 0 | STOP | （无值） |
| 1 | BOOL_TRUE | （无值 — 编码在头字节中） |
| 2 | BOOL_FALSE | （无值 — 编码在头字节中） |
| 3 | BYTE | 1 字节原始值 |
| 4 | I16 | zigzag → varint |
| 5 | I32 | zigzag → varint |
| 6 | I64 | zigzag → varint |
| 7 | DOUBLE | 8 字节原始值 |
| 8 | BINARY/STRING | varint 长度 + 字节内容 |
| 9 | LIST | 元素类型/大小字节 + varint 计数 + 元素 |
| 10 | SET | 同 LIST |
| 11 | MAP | varint 计数 + 键值类型字节 + 键值对 |
| 12 | STRUCT | 嵌套字段 + STOP |

### Zigzag 编码

所有整数类型在 varint 序列化前使用 zigzag 编码：

```
编码: (n << 1) ^ (n >> (位宽 - 1))
解码: (v >> 1) ^ -(v & 1)
```

| 原始值 | 编码值 | varint 字节数 |
|--------|--------|---------------|
| 0 | 0 | 1 |
| -1 | 1 | 1 |
| 1 | 2 | 1 |
| -2 | 3 | 1 |
| 127 | 254 | 2 |
| -128 | 255 | 2 |

不做 zigzag 的话，`-1` 作为原始 i32 会编码为 10 字节的 varint（`ff ff ff ff ff ff ff ff ff 01`）。做了 zigzag 后只需 1 字节（`01`）。

### LIST 编码

第一个字节同时编码元素类型和数量：

```
数量 ≤ 14: (count << 4) | elem_type
数量 > 15: 0xF0 | elem_type, 后跟 varint count
```

### Bool 编码

布尔值比较特殊——不使用单独的值字节，而是直接编码在字段头的类型字段中：

```
BOOL_TRUE:  头字节 = (delta << 4) | 0x01
BOOL_FALSE: 头字节 = (delta << 4) | 0x02
```

后面不跟值字节。读取器必须在 `read_field_begin()` 中检测类型 1/2 并设置标志位，然后在 `read_bool()` 中返回该标志。

### Hex Dump 解析示例

解析一个 `createSession` 响应：

```
82 01 00 0f 63 72 65 61 74 65 53 65 73 73 69 6f 6e 0c 01 00 00 0b 01 00 21 30 38 ...
```

| 字节 | 字段 | 值 |
|------|------|-----|
| `82` | 协议 ID | TCompact |
| `01` | 版本/类型 | version=1, msg_type=0 |
| `00` | 序列号 | 0（zigzag 编码的 0） |
| `0f` | 方法名长度 | 15 字节 |
| `63 72 65 61 74 65 53 65 73 73 69 6f 6e` | 方法名 | "createSession" |
| `0c` | 字段头 | delta=0, type=STRUCT (12) |
| `01` | 嵌套字段 | delta=1, type=BOOL_TRUE |
| `00` | STOP | 内层结构体结束 |
| `00` | STOP | 外层结构体结束 |

响应将实际的 session 数据包装在嵌套结构体中（外层结构体的字段 1）。内层结构体中，字段 1 是布尔成功标志，后续字段中包含 session ID。

## 七阶段 QR 登录握手

### 阶段 1: createSession

**Thrift 类型**：`ek1/k`（空请求）→ 包装在 `ek1/m0` 中（字段 1 = STRUCT）

```java
// 请求包装器 (ek1/m0)
m0 req = new m0();
k inner = new k();  // 空 — 无字段
req.f86603a = inner;
```

**响应类型**：`ek1/l` — 字段 1 (STRING) = `authSessionId`

Session ID 是一个类 UUID 的字符串，标识本次登录尝试。后续所有调用都引用它。

### 阶段 2: createQrCodeForSecure

**请求类型**：`ek1/j` → 包装在 `ek1/k0` 中
- 字段 1 (STRING): `authSessionId`

```java
// ek1/j
j req = new j();
req.f86577a = sessionId;  // 字段 1

// ek1/k0 包装器
k0 wrapper = new k0();
wrapper.f86589a = req;     // 字段 1 = STRUCT
```

**响应类型**：`ek1/i`
- 字段 1 (STRING): `callbackUrl`
- 字段 2 (I32): `longPollingMaxCount`
- 字段 3 (I32): `longPollingIntervalSec`
- 字段 4 (BINARY): `nonce`（32 字节）

`callbackUrl` 是 QR 码的基础 URL。`nonce` 是服务器生成的随机值。两者都需要，但用途不同——URL 需要附加 E2EE 公钥（见密钥交换章节），而 nonce 在后续登录流程中使用。

### 阶段 3: checkQrCodeVerified

**请求**：与阶段 1 相同的模式 — `authSessionId` 作为字段 1。

**响应**：成功时返回空结构体（无字段），失败时返回 `TalkException`（响应的字段 1）。

这是长轮询调用 — 使用 `/acct/lp/lgn/sq/v1` 端点，带 `x-lst: 150000`。服务器保持 TCP 连接直到用户在手机上扫描 QR 码，然后返回空成功。

**已知问题**：服务器有时在约 7 秒后返回空成功，即使用户尚未扫描。这似乎与 HTTP/2 连接处理有关——APK 使用 OkHttp 的 `ConnectionPool(5, 60s)` 和 HTTP/2 多路复用，这可能影响服务器端的超时行为。

### 阶段 4: verifyCertificate

**请求类型**：`ek1/t0` → 包装在 `ek1/q0` 中
- 字段 1 (STRING): `authSessionId`
- 字段 2 (STRING): `certificate`（可选，来自上次登录）

**响应类型**：`ek1/u0`

用于已有保存证书的回访用户。如果证书有效，阶段 5-6 将被跳过。

### 阶段 5: createPinCode

**请求类型**：`ek1/g` → 包装在 `ek1/i0` 中
- 字段 1 (STRING): `authSessionId`

```java
// ek1/g
g req = new g();
req.f86548a = sessionId;  // 字段 1

// ek1/i0 包装器
i0 wrapper = new i0();
wrapper.f86573a = req;     // 字段 1 = STRUCT
```

**响应类型**：`ek1/h`
- 字段 1 (STRING): `pinCode`（6 位数字字符串）

**错误处理**：如果手机尚未扫描 QR 码，返回 `TalkException`，错误码 100（`INVALID_CONTEXT`）。APK 以循环方式重试——这是预期行为，不是错误。

### 阶段 6: checkPinCodeVerified

与阶段 3 相同的长轮询机制。等待用户在手机上输入 PIN 码。使用相同的端点和请求头。

### 阶段 7: qrCodeLoginV2ForSecure

**请求类型**：`ek1/p` → 包装在 `ek1/o0` 中
- 字段 1 (STRING): `authSessionId`
- 字段 2 (STRING): `systemName` — 设备名称
- 字段 3 (STRING): `modelName` — 设备型号
- 字段 4 (BOOL): `autoLoginIsRequired` — 固定为 `true`
- 字段 5 (STRING): `nonce` — 阶段 5 获取的 PIN 码

```java
// ek1/p
p req = new p();
req.f86631a = sessionId;    // 字段 1
req.f86632c = systemName;   // 字段 2
req.f86633d = modelName;    // 字段 3
req.f86634e = true;          // 字段 4 (autoLoginIsRequired)
req.f86635f = pinCode;       // 字段 5 (nonce = PIN 码)
```

**响应类型**：`ek1/q`
- 字段 1 (STRING): `certificate` — 保存用于后续登录
- 字段 2 (STRING): `accessTokenV2` — 用于 `X-Line-Access` 请求头
- 字段 3 (STRUCT): `tokenV3IssueResult`
- 字段 4 (STRING): `mid` — 用户内部 ID
- 字段 9 (I64): `lastBindTimestamp`
- 字段 10 (MAP): `metaData` — map<string, string>

`accessTokenV2` 是后续所有 API 调用的凭证。

## E2EE 密钥交换（Curve25519）

### 密钥对生成

来自 `q94/c.java`：

```java
public static a generateKeyPair() {
    byte[] publicKey = new byte[32];
    byte[] privateKey = new byte[32];
    new SecureRandom().nextBytes(privateKey);

    // Curve25519 标准钳位操作
    byte b = (byte) (privateKey[31] & 0x7f);  // 清除第 255 位
    privateKey[31] = (byte) (b | 0x40);        // 设置第 254 位
    privateKey[0]  = (byte) (privateKey[0] & 0xf8);  // 清除第 0-2 位

    // 标量乘法: publicKey = privateKey * basepoint
    q94.a.b(publicKey, privateKey, null);
    return new a(publicKey, privateKey);
}
```

钳位操作确保私钥是有效的 Curve25519 标量：
- 清除第 255 位，设置第 254 位 → 确保标量在 `[2^254, 2^255)` 范围内
- 清除第 0-2 位 → 确保标量是 8 的倍数（余因子）

### QR URL 构造

公钥作为 `secret` 参数嵌入 QR URL：

```java
// 来自 rz2/t$p（阶段 2 的处理函数）
String secret = URLEncoder.encode(
    Base64.encodeToString(sessionData.keyPair.publicKey, 0),
    "UTF-8"
);
String qrUrl = callbackUrl + "?secret=" + secret + "&e2eeVersion=1";
```

`secret` **不是** createQrCodeForSecure 响应中的 `nonce`。两者都是 32 字节，都是二进制数据，都出现在同一个响应中。在混淆代码中，`q94.c.a` 密钥对结构体的字段名为 `f164966a`（公钥）和 `f164967b`（私钥）。

### ECDH 共享密钥

手机扫描 QR 码时，从 `secret` 参数中提取公钥，生成自己的密钥对，然后计算共享密钥：

```
sharedSecret = ECDH(phonePrivateKey, qrPublicKey)
             = ECDH(qrPrivateKey, phonePublicKey)
```

### 密钥派生

使用 SHA-256 和域名分离从共享密钥派生两个密钥：

```java
// q94/c.java

// AES 密钥: SHA-256(sharedSecret) → XOR 折叠为 16 字节
static byte[] deriveKey(byte[] sharedSecret) {
    byte[] hash = SHA256(sharedSecret);
    byte[] key = new byte[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (byte) (hash[i] ^ hash[i + 16]);
    }
    return key;
}

// IV: SHA-256(sharedSecret || otherPubKey || "IV") → XOR 折叠为 16 字节
static byte[] deriveIV(byte[] sharedSecret, byte[] otherPubKey) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(sharedSecret);
    if (otherPubKey != null) md.update(otherPubKey);
    md.update("IV".getBytes());  // 域名分离
    byte[] hash = md.digest();
    byte[] iv = new byte[16];
    for (int i = 0; i < 16; i++) {
        iv[i] = (byte) (hash[i] ^ hash[i + 16]);
    }
    return iv;
}

// 完整密钥派生
static byte[] deriveFullKey(byte[] sharedSecret, byte[] otherPubKey) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(sharedSecret);
    if (otherPubKey != null) md.update(otherPubKey);
    md.update("Key".getBytes());  // 域名分离
    return md.digest();
}
```

域名分离字符串 `"Key"` 和 `"IV"` 被追加到 SHA-256 输入中，防止同一共享密钥在加密和 IV 生成中产生相同的密钥材料。

### AES 加密

APK 使用 AES-CBC 和 PKCS5 填充：

```java
static byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    return cipher.doFinal(plaintext);
}
```

## TalkException 错误码

当 Thrift 调用失败时，服务器返回 `TalkException` 结构体：

```
字段 1 (I32):    code
字段 2 (STRING): reason
```

| 代码 | 名称 | 含义 |
|------|------|------|
| 0 | INTERNAL_ERROR | 服务器内部错误 |
| 1 | ILLEGAL_ARGUMENT | 请求格式错误 |
| 2 | VERIFICATION_FAILED | 认证验证失败 |
| 3 | NOT_ALLOWED_QR_CODE_LOGIN | 该账号禁止 QR 登录 |
| 100 | INVALID_CONTEXT | QR 码过期或会话状态错误 |
| 101 | APP_UPGRADE_REQUIRED | 客户端版本过旧 |

`createPinCode` 中的错误码 100 是**预期行为**——表示手机尚未扫描 QR 码。APK 以指数退避方式重试直到成功。

## Thrift 类型参考

`ek1` 包中的关键请求/响应类型：

| 类名 | 方法 | 关键字段 |
|------|------|----------|
| `ek1/k` | CreateSessionRequest | （空） |
| `ek1/l` | CreateSessionResponse | 字段 1: authSessionId (STRING) |
| `ek1/j` | CreateQrCodeForSecureRequest | 字段 1: authSessionId (STRING) |
| `ek1/i` | CreateQrCodeForSecureResponse | 字段 1: callbackUrl, 字段 4: nonce (BINARY) |
| `ek1/g` | CreatePinCodeRequest | 字段 1: authSessionId (STRING) |
| `ek1/h` | CreatePinCodeResponse | 字段 1: pinCode (STRING) |
| `ek1/p` | QrCodeLoginV2ForSecureRequest | 字段 1-5: session, 设备, PIN |
| `ek1/q` | QrCodeLoginV2ForSecureResponse | 字段 1: cert, 字段 2: token, 字段 4: mid |
| `ek1/t0` | VerifyCertificateRequest | 字段 1: sessionId, 字段 2: certificate |
| `ek1/u0` | VerifyCertificateResponse | （证书验证结果） |
| `ek1/s` | TalkException | 字段 1: code (I32), 字段 2: reason (STRING) |

每个请求类型都被包装在一个外层结构体中用于 Thrift 调用。包装器类型遵循以下模式：`ek1/m0` 对应 createSession，`ek1/k0` 对应 createQrCode，`ek1/i0` 对应 createPinCode，`ek1/o0` 对应 qrLoginV2，`ek1/q0` 对应 verifyCertificate。包装器的字段 1 始终是内层请求结构体。

---

*基于 LINE Android APK v14.x 的静态分析（使用 jadx 反编译）。协议细节可能在后续版本中发生变化。*
