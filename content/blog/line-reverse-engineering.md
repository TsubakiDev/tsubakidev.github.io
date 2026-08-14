+++
title = "Reverse Engineering LINE's QR Login Protocol"
date = 2026-06-02
description = "A technical analysis of LINE's QR code authentication protocol — Thrift TCompact wire format, Curve25519 E2EE key exchange, and the seven-stage login handshake."
[taxonomies]
tags = ["reverse-engineering", "line", "thrift", "cryptography", "android"]
+++

## Overview

LINE's desktop authentication uses a seven-stage QR code handshake over a custom Thrift TCompact binary protocol. This post documents the protocol internals based on static analysis of the Android APK (decompiled with jadx) and packet inspection.

The key components:

| Decompiled Class | Role |
|---|---|
| `rz2/t.java` | QR login ViewModel — 7-stage state machine |
| `zz2/p.java` | `SecondaryQrCodeLoginServiceClient` — Thrift RPC for normal requests |
| `zz2/k.java` | Long-poll variant of the service client |
| `tz2/j.java` | Repository — API method orchestration |
| `q94/c.java` | Curve25519 keypair + AES/SHA-256 crypto primitives |
| `ek1/*.java` | Thrift-generated request/response types |

## API Endpoints

Two separate service endpoints, both on `legy-jp.line-apps.com`:

```
Normal:     POST https://legy-jp.line-apps.com/acct/lgn/sq/v1
Long-poll:  POST https://legy-jp.line-apps.com/acct/lp/lgn/sq/v1
```

The `zz2/p` client handles normal request-response calls. The `zz2/k` client handles long-poll calls (`checkQrCodeVerified`, `checkPinCodeVerified`). Both use the same Thrift serialization but differ in HTTP timeout handling.

## Required Headers

```
Content-Type: application/x-thrift; protocol=TCOMPACT
User-Agent: Line/8.7.0
X-Line-Application: DESKTOPMAC\t8.7.0\tMAC\t10.15.7
x-lal: ja_JP
x-lhm: POST
```

For authenticated requests:
```
X-Line-Access: <accessToken or sessionId>
```

For long-poll requests:
```
x-lst: 150000
```

The `X-Line-Application` format is `PLATFORM\tVERSION\tOS\tOS_VERSION` with literal tab characters (`0x09`). The `x-lst` header specifies the long-poll timeout in milliseconds — the server holds the TCP connection open for up to this duration.

## Thrift TCompact Wire Protocol

LINE uses Apache Thrift's TCompact protocol, not TBinary. The encoding is significantly more space-efficient due to delta-encoded field IDs and zigzag-encoded integers.

### Message Framing

```
+----------+----------+--------+-----------+
| Proto ID | Ver/Type | SeqID  | Method    |
| 0x82     | 1 byte   | varint | string    |
+----------+----------+--------+-----------+
```

**Protocol ID**: Always `0x82`.

**Version/Type byte**: `(message_type << 5) | version`
- Bits 7-5: message type (1=CALL, 2=REPLY, 3=EXCEPTION, 4=ONEWAY)
- Bits 4-0: version (always 1)

**SeqID**: zigzag-encoded i32 as varint.

**Method name**: length-prefixed UTF-8 string (varint length, then bytes).

### Field Header Encoding

Each field within a struct starts with a header byte:

```
Short form: (delta << 4) | field_type    [1 byte, when 1 ≤ delta ≤ 15]
Long form:  (0x00 | field_type) + i16    [3 bytes, when delta = 0 or > 15]
```

`delta` = `current_field_id - previous_field_id`. The previous field ID is tracked per-struct and resets to 0 at each `STRUCT_BEGIN`.

### Type Constants

| Code | Type | Encoding |
|------|------|----------|
| 0 | STOP | (no value) |
| 1 | BOOL_TRUE | (no value — encoded in header) |
| 2 | BOOL_FALSE | (no value — encoded in header) |
| 3 | BYTE | 1 byte raw |
| 4 | I16 | zigzag → varint |
| 5 | I32 | zigzag → varint |
| 6 | I64 | zigzag → varint |
| 7 | DOUBLE | 8 bytes raw |
| 8 | BINARY/STRING | varint length + bytes |
| 9 | LIST | elem_type_size byte + varint count + elements |
| 10 | SET | same as LIST |
| 11 | MAP | varint count + kv_types byte + key/value pairs |
| 12 | STRUCT | nested fields + STOP |

### Zigzag Encoding

All integer types use zigzag encoding before varint serialization:

```
Encode:  (n << 1) ^ (n >> (bitwidth - 1))
Decode:  (v >> 1) ^ -(v & 1)
```

| Original | Encoded | Varint bytes |
|----------|---------|--------------|
| 0 | 0 | 1 |
| -1 | 1 | 1 |
| 1 | 2 | 1 |
| -2 | 3 | 1 |
| 127 | 254 | 2 |
| -128 | 255 | 2 |

Without zigzag, `-1` as a raw i32 would varint-encode to 10 bytes (`ff ff ff ff ff ff ff ff ff 01`). With zigzag, it's 1 byte (`01`).

### List Encoding

The first byte encodes both element type and count:

```
If count ≤ 14:  (count << 4) | elem_type
If count > 15:  0xF0 | elem_type, followed by varint count
```

### Bool Encoding

Booleans are encoded in the field header itself, not as a separate value byte. When writing a bool, the writer defers the header byte until the value is known:

```
BOOL_TRUE:  header byte = (delta << 4) | 0x01
BOOL_FALSE: header byte = (delta << 4) | 0x02
```

No value byte follows. The reader must detect type 1/2 in `read_field_begin()` and set a flag, then return the flag from `read_bool()`.

### Hex Dump Walkthrough

Parsing a `createSession` response:

```
82 01 00 0f 63 72 65 61 74 65 53 65 73 73 69 6f 6e 0c 01 00 00 0b 01 00 21 30 38 ...
```

| Bytes | Field | Value |
|-------|-------|-------|
| `82` | Protocol ID | TCompact |
| `01` | Version/Type | version=1, msg_type=0 |
| `00` | SeqID | 0 (zigzag of 0) |
| `0f` | Method name length | 15 bytes |
| `63 72 65 61 74 65 53 65 73 73 69 6f 6e` | Method name | "createSession" |
| `0c` | Field header | delta=0, type=STRUCT (12) |
| `01` | Nested field | delta=1, type=BOOL_TRUE |
| `00` | STOP | end of inner struct |
| `00` | STOP | end of outer struct |

The response wraps the actual session data in a nested struct (field ID 1 of the outer struct). Inside, field 1 of the inner struct is a boolean success flag, and the session ID appears in a subsequent field.

## Seven-Stage QR Login Handshake

~~~mermaid
flowchart LR
    Session["1. createSession"] --> QR["2. createQrCodeForSecure"]
    QR --> Scan["3. checkQrCodeVerified"]
    Scan --> Certificate["4. verifyCertificate"]
    Certificate --> Pin["5. createPinCode"]
    Pin --> PinCheck["6. checkPinCodeVerified"]
    PinCheck --> Login["7. qrCodeLoginV2ForSecure"]
~~~

### Stage 1: createSession

**Thrift type**: `ek1/k` (empty request) → wrapped in `ek1/m0` (field 1 = STRUCT)

```java
// Request wrapper (ek1/m0)
m0 req = new m0();
k inner = new k();  // empty — no fields
req.f86603a = inner;
```

**Response type**: `ek1/l` — field 1 (STRING) = `authSessionId`

The session ID is a UUID-like string that identifies this login attempt. All subsequent calls reference it.

### Stage 2: createQrCodeForSecure

**Request type**: `ek1/j` → wrapped in `ek1/k0`
- Field 1 (STRING): `authSessionId`

```java
// ek1/j
j req = new j();
req.f86577a = sessionId;  // field 1

// ek1/k0 wrapper
k0 wrapper = new k0();
wrapper.f86589a = req;     // field 1 = STRUCT
```

**Response type**: `ek1/i`
- Field 1 (STRING): `callbackUrl`
- Field 2 (I32): `longPollingMaxCount`
- Field 3 (I32): `longPollingIntervalSec`
- Field 4 (BINARY): `nonce` (32 bytes)

The `callbackUrl` is the base QR URL. The `nonce` is a server-generated random value. Both are needed, but for different purposes — the URL needs the E2EE public key appended (see Key Exchange section), while the nonce is used later in the login flow.

### Stage 3: checkQrCodeVerified

**Request**: Same as stage 1 pattern — `authSessionId` as field 1.

**Response**: Empty success struct (no fields) on success, or `TalkException` (field 1 of the response) on failure.

This is a long-poll call — uses the `/acct/lp/lgn/sq/v1` endpoint with `x-lst: 150000`. The server holds the TCP connection until the user scans the QR on their phone, then returns an empty success.

**Known issue**: The server sometimes returns after ~7 seconds with empty success even without a scan. This appears to be related to HTTP/2 connection handling — the APK uses OkHttp with `ConnectionPool(5, 60s)` and HTTP/2 multiplexing, which may affect server-side timeout behavior.

### Stage 4: verifyCertificate

**Request type**: `ek1/t0` → wrapped in `ek1/q0`
- Field 1 (STRING): `authSessionId`
- Field 2 (STRING): `certificate` (optional, from previous login)

**Response type**: `ek1/u0`

For returning users with a saved certificate. If valid, stages 5-6 are skipped.

### Stage 5: createPinCode

**Request type**: `ek1/g` → wrapped in `ek1/i0`
- Field 1 (STRING): `authSessionId`

```java
// ek1/g
g req = new g();
req.f86548a = sessionId;  // field 1

// ek1/i0 wrapper
i0 wrapper = new i0();
wrapper.f86573a = req;     // field 1 = STRUCT
```

**Response type**: `ek1/h`
- Field 1 (STRING): `pinCode` (6-digit string)

**Error handling**: Returns `TalkException` with code 100 (`INVALID_CONTEXT`) if the phone hasn't scanned the QR yet. The APK retries in a loop — this is expected, not a failure.

### Stage 6: checkPinCodeVerified

Same long-poll mechanics as stage 3. Waits for the user to enter the PIN on their phone. Uses the same endpoint and headers.

### Stage 7: qrCodeLoginV2ForSecure

**Request type**: `ek1/p` → wrapped in `ek1/o0`
- Field 1 (STRING): `authSessionId`
- Field 2 (STRING): `systemName` — device name
- Field 3 (STRING): `modelName` — device model
- Field 4 (BOOL): `autoLoginIsRequired` — always `true`
- Field 5 (STRING): `nonce` — the PIN code from stage 5

```java
// ek1/p
p req = new p();
req.f86631a = sessionId;    // field 1
req.f86632c = systemName;   // field 2
req.f86633d = modelName;    // field 3
req.f86634e = true;          // field 4 (autoLoginIsRequired)
req.f86635f = pinCode;       // field 5 (nonce = PIN)
```

**Response type**: `ek1/q`
- Field 1 (STRING): `certificate` — save for future logins
- Field 2 (STRING): `accessTokenV2` — used in `X-Line-Access` header
- Field 3 (STRUCT): `tokenV3IssueResult`
- Field 4 (STRING): `mid` — user's internal ID
- Field 9 (I64): `lastBindTimestamp`
- Field 10 (MAP): `metaData` — map<string, string>

The `accessTokenV2` is the credential for all subsequent API calls.

## E2EE Key Exchange (Curve25519)

### Keypair Generation

From `q94/c.java`:

```java
public static a generateKeyPair() {
    byte[] publicKey = new byte[32];
    byte[] privateKey = new byte[32];
    new SecureRandom().nextBytes(privateKey);

    // Curve25519 clamping (standard)
    byte b = (byte) (privateKey[31] & 0x7f);  // Clear bit 255
    privateKey[31] = (byte) (b | 0x40);        // Set bit 254
    privateKey[0]  = (byte) (privateKey[0] & 0xf8);  // Clear bits 0-2

    // Scalar multiplication: publicKey = privateKey * basepoint
    q94.a.b(publicKey, privateKey, null);
    return new a(publicKey, privateKey);
}
```

The clamping ensures the private key is a valid Curve25519 scalar:
- Bit 255 cleared, bit 254 set → ensures the scalar is in `[2^254, 2^255)`
- Bits 0-2 cleared → ensures the scalar is a multiple of 8 (cofactor)

### QR URL Construction

The public key is embedded in the QR URL as the `secret` parameter:

```java
// From rz2/t$p (the stage 2 handler)
String secret = URLEncoder.encode(
    Base64.encodeToString(sessionData.keyPair.publicKey, 0),
    "UTF-8"
);
String qrUrl = callbackUrl + "?secret=" + secret + "&e2eeVersion=1";
```

The `secret` is **not** the `nonce` from the createQrCodeForSecure response. Both are 32 bytes, both are binary, both appear in the same response. The field names in the obfuscated code are `f164966a` (publicKey) and `f164967b` (privateKey) in the `q94.c.a` keypair struct.

### ECDH Shared Secret

When the phone scans the QR, it extracts the public key from the `secret` parameter, generates its own keypair, and computes the shared secret:

```
sharedSecret = ECDH(phonePrivateKey, qrPublicKey)
             = ECDH(qrPrivateKey, phonePublicKey)
```

### Key Derivation

Two keys are derived from the shared secret using SHA-256 with domain separation:

```java
// q94/c.java

// AES key: SHA-256(sharedSecret) → XOR fold to 16 bytes
static byte[] deriveKey(byte[] sharedSecret) {
    byte[] hash = SHA256(sharedSecret);
    byte[] key = new byte[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (byte) (hash[i] ^ hash[i + 16]);
    }
    return key;
}

// IV: SHA-256(sharedSecret || otherPubKey || "IV") → XOR fold to 16 bytes
static byte[] deriveIV(byte[] sharedSecret, byte[] otherPubKey) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(sharedSecret);
    if (otherPubKey != null) md.update(otherPubKey);
    md.update("IV".getBytes());  // domain separation
    byte[] hash = md.digest();
    byte[] iv = new byte[16];
    for (int i = 0; i < 16; i++) {
        iv[i] = (byte) (hash[i] ^ hash[i + 16]);
    }
    return iv;
}

// Full key derivation
static byte[] deriveFullKey(byte[] sharedSecret, byte[] otherPubKey) {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(sharedSecret);
    if (otherPubKey != null) md.update(otherPubKey);
    md.update("Key".getBytes());  // domain separation
    return md.digest();
}
```

The domain separation strings `"Key"` and `"IV"` are appended to the SHA-256 input to prevent the same shared secret from producing identical key material for encryption and IV generation.

### AES Encryption

The APK uses AES-CBC with PKCS5 padding:

```java
static byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    return cipher.doFinal(plaintext);
}
```

## TalkException Error Codes

When a Thrift call fails, the server returns a `TalkException` struct:

```
Field 1 (I32):    code
Field 2 (STRING): reason
```

| Code | Name | Meaning |
|------|------|---------|
| 0 | INTERNAL_ERROR | Server internal error |
| 1 | ILLEGAL_ARGUMENT | Malformed request |
| 2 | VERIFICATION_FAILED | Auth verification failed |
| 3 | NOT_ALLOWED_QR_CODE_LOGIN | QR login disabled for this account |
| 100 | INVALID_CONTEXT | QR expired or wrong session state |
| 101 | APP_UPGRADE_REQUIRED | Client version too old |

Code 100 during `createPinCode` is **expected** — it means the phone hasn't scanned the QR yet. The APK retries with exponential backoff until the call succeeds.

## Thrift Type Reference

Key request/response types from the `ek1` package:

| Class | Method | Key Fields |
|-------|--------|------------|
| `ek1/k` | CreateSessionRequest | (empty) |
| `ek1/l` | CreateSessionResponse | field 1: authSessionId (STRING) |
| `ek1/j` | CreateQrCodeForSecureRequest | field 1: authSessionId (STRING) |
| `ek1/i` | CreateQrCodeForSecureResponse | field 1: callbackUrl, field 4: nonce (BINARY) |
| `ek1/g` | CreatePinCodeRequest | field 1: authSessionId (STRING) |
| `ek1/h` | CreatePinCodeResponse | field 1: pinCode (STRING) |
| `ek1/p` | QrCodeLoginV2ForSecureRequest | field 1-5: session, device, PIN |
| `ek1/q` | QrCodeLoginV2ForSecureResponse | field 1: cert, field 2: token, field 4: mid |
| `ek1/t0` | VerifyCertificateRequest | field 1: sessionId, field 2: certificate |
| `ek1/u0` | VerifyCertificateResponse | (certificate validation result) |
| `ek1/s` | TalkException | field 1: code (I32), field 2: reason (STRING) |

Each request type is wrapped in an outer struct for the Thrift call. The wrapper types follow the pattern `ek1/m0` for createSession, `ek1/k0` for createQrCode, `ek1/i0` for createPinCode, `ek1/o0` for qrLoginV2, `ek1/q0` for verifyCertificate. The wrapper's field 1 is always the inner request struct.

---

*Based on static analysis of LINE Android APK v14.x (decompiled with jadx). Protocol details may change in future versions.*
