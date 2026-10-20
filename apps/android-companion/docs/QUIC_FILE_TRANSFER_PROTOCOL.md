# Tether QUIC File Sharing Wire Protocol Specification (`tether-quic-v1`)

## 1. Overview & Transport Protocol

Tether QUIC File Sharing is an application-level peer-to-peer file transfer protocol built over QUIC (RFC 9000) with TLS 1.3 encryption.

- **ALPN Identifier:** `"tether-quic-v1"`
- **Default UDP Port:** `37125`
- **Session Transport:** Single QUIC Connection (`QuicConnection` in .NET 8 / `TetherQuicConnection` on Android)

### Endpoints
- **Client (Sender/Initiator):** Connects to remote endpoint on UDP 37125.
- **Server (Receiver/Listener):** Listens on UDP 37125.

---

## 2. Authentication & Peer Validation

1. **TLS 1.3 Handshake Validation:**
   - Both client and server present their identity public key inside their X.509 certificate.
   - Upon receiving the peer certificate, the endpoint extracts the leaf public key bytes and computes its SHA-256 fingerprint:
     `Fingerprint = SHA-256(PublicKeyBytes)`
   - The fingerprint is matched against the locally pinned device public key (`ProductionSecurityEngine.getPinnedKeyDecrypted()`).
   - If the public key does not match or the peer is unpaired, the TLS handshake is immediately aborted.
2. **0-RTT Restrictions:**
   - Early data (0-RTT) is **disabled** for file creation, overwrites, and state-changing requests to prevent replay attacks.

---

## 3. Stream Allocation & Framing Rules

QUIC provides stream multiplexing. Stream ownership rules are defined as follows:

### 3.1 Control Stream (Client-Initiated Bidirectional Stream 0)
- Opened by the client immediately upon establishing the QUIC connection.
- **Control Handshake:**
  1. Client sends `CONTROL_INIT`:
     ```json
     {
       "type": "CONTROL_INIT",
       "protocolVersion": "1.0",
       "deviceId": "<clientPhoneFingerprint>"
     }
     ```
  2. Server responds with `CONTROL_INIT_ACK`:
     ```json
     {
       "type": "CONTROL_INIT_ACK",
       "status": "OK",
       "grantedCapabilities": "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA"
     }
     ```
- **Stream Framing:** All control frames are UTF-8 JSON payloads preceded by a 4-byte Big-Endian Length Prefix:
  `[4 bytes Big-Endian Length Prefix (uint32)][UTF-8 JSON Payload]`
  - Maximum control payload length: **65,536 bytes (64 KB)**.
  - Exceeding limit terminates connection with QUIC transport error `0x0A` (`PROTOCOL_VIOLATION`).
- Only **one** control stream is permitted per QUIC connection. Any secondary control stream attempt is closed with QUIC error `0x02` (`STREAM_CREATION_ERROR`).

### 3.2 Data Stream (Client-Initiated Unidirectional Stream)
- Opened by the sender after receiving `TRANSFER_RESPONSE` with status `ACCEPTED` or `RESUME_ACK`.
- Transmits binary file chunks concurrently with control stream messages.

#### Binary Chunk Frame Layout (29-byte Header + Payload):
`[4 bytes Big-Endian Frame Length][1 byte MsgType = 0x01][16 bytes UUID transferId][8 bytes Big-Endian chunkIndex][8 bytes Big-Endian offset][4 bytes Payload Length][Binary Payload Bytes]`

#### End-of-Stream Signal:
`[4 bytes Big-Endian Frame Length = 17][1 byte MsgType = 0x02 DATA_END][16 bytes UUID transferId]` followed by QUIC stream FIN flag.

---

## 4. Control Messages

### 4.1 `TRANSFER_REQUEST`
```json
{
  "type": "TRANSFER_REQUEST",
  "version": "1.0",
  "transferId": "550e8400-e29b-41d4-a716-446655440000",
  "fileName": "example.pdf",
  "fileSize": 10485760,
  "mimeType": "application/pdf",
  "expectedSha512": "3C0123...HEX_UPPERCASE...",
  "chunkSize": 65536,
  "totalChunks": 160,
  "sourceLastModified": 1718000000000
}
```

### 4.2 `TRANSFER_RESPONSE`
```json
{
  "type": "TRANSFER_RESPONSE",
  "transferId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ACCEPTED",
  "resumeOffset": 0,
  "errorCode": 0,
  "reason": ""
}
```

### 4.3 `TRANSFER_RESUME_REQUEST`
```json
{
  "type": "TRANSFER_RESUME_REQUEST",
  "transferId": "550e8400-e29b-41d4-a716-446655440000",
  "requestedOffset": 1048576,
  "sourceLastModified": 1718000000000,
  "sourceSize": 10485760
}
```

### 4.4 `TRANSFER_RESUME_ACK`
```json
{
  "type": "TRANSFER_RESUME_ACK",
  "transferId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ACCEPTED",
  "resumeOffset": 1048576,
  "partialSha512": "8F912...HEX_UPPERCASE...",
  "errorCode": 0,
  "reason": ""
}
```

### 4.5 `TRANSFER_COMPLETE`
```json
{
  "type": "TRANSFER_COMPLETE",
  "transferId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "SUCCESS",
  "errorCode": 0,
  "reason": ""
}
```

---

## 5. Application Error Codes

| Code | Name | Description |
| :--- | :--- | :--- |
| `0x10` | `UNAUTHORIZED_PEER` | Peer public key does not match pinned identity |
| `0x11` | `MISSING_CAPABILITY` | Peer lacks granted `FILES` capability |
| `0x12` | `PATH_TRAVERSAL_REJECTED` | Unsafe filename path traversal detected |
| `0x13` | `DISK_FULL` | Insufficient storage space on receiver |
| `0x14` | `INTEGRITY_FAILED` | Complete file SHA-512 digest mismatch |
| `0x15` | `RESUME_PREFIX_MISMATCH` | Partial file prefix digest mismatch during resume |
| `0x16` | `SOURCE_FILE_CHANGED` | Source file length or timestamp changed |
| `0x17` | `USER_CANCELLED` | Transfer explicitly cancelled by user |
| `0x18` | `SERVICE_TIMEOUT` | System execution time limit reached |

---

## 6. C# .NET 8 Implementation Notes (`System.Net.Quic`)

1. **Listener Setup:**
   ```csharp
   var listener = await QuicListener.ListenAsync(new QuicListenerOptions {
       ListenEndPoint = new IPEndPoint(IPAddress.Any, 37125),
       ApplicationProtocols = new List<SslApplicationProtocol> { new SslApplicationProtocol("tether-quic-v1") },
       ConnectionOptionsCallback = (connection, info, cancellationToken) => ValueTask.FromResult(new QuicServerConnectionOptions {
           ServerAuthenticationOptions = new SslServerAuthenticationOptions {
               ServerCertificate = winIdentityCert,
               RemoteCertificateValidationCallback = ValidatePeerPublicKeyPin
           }
       })
   });
   ```
2. **Stream Reading:** Use `QuicStream.ReadAsync(Memory<byte>)` with 64 KB buffers.
3. **SHA-512 Hash:** Use `System.Security.Cryptography.SHA512.Create()` incrementally.
