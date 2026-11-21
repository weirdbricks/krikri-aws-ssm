# SSM Session Manager wire protocol (working notes)

Status: working spec transcribed from the reference implementations. Phase 1
pins every constant below with tests taken from the sources - nothing here may
be "confirmed" against this shard's own output. AWS publishes the control
plane only; the data channel is defined by `aws/session-manager-plugin`
(Apache-2.0) and documented by observation in `hupe1980/aws-ssm-bridge` (MIT).
See `NOTICE`.

## Control plane

`ssm:StartSession` (JSON 1.1, SigV4 over `ssm`) returns `SessionId`,
`StreamUrl`, `TokenValue`. `ResumeSession` returns a fresh URL/token for the
same session; `TerminateSession` ends it.

## Data-channel upgrade

- Dial `StreamUrl` with a manual websocket upgrade so the `Host` header that is
  signed is the exact value sent (Crystal's stdlib rewrites it as
  `host:port`).
- SigV4 over `ssmmessages`, GET, empty payload hash, `add_sha: false`. Sign only
  the headers present on the request: `host`, `X-Amz-Date`, and
  `X-Amz-Security-Token` when a session token exists.
- If the URL is presigned (`X-Amz-Signature`, `X-Amz-Credential`, ...), dial it
  unsigned, like the reference `IsPresignedURL` branch.
- First frame is a websocket TEXT message:

```json
{
  "MessageSchemaVersion": "1.0",
  "RequestId": "<uuid>",
  "TokenValue": "<token>",
  "ClientId": "<uuid>",
  "ClientVersion": "1.0.0"
}
```

## Frame format

120-byte header, big-endian integers, then payload.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | HeaderLength | 116 (excludes this field) |
| 4 | 32 | MessageType | ASCII, space-padded |
| 36 | 4 | SchemaVersion | 1 |
| 40 | 8 | CreatedDate | Unix milliseconds |
| 48 | 8 | SequenceNumber | per direction, starts at 0 |
| 56 | 8 | Flags | SYN = 1, FIN = 2 |
| 64 | 16 | MessageId | UUID, least-significant half first |
| 80 | 32 | PayloadDigest | SHA-256 of the payload as sent |
| 112 | 4 | PayloadType | see below |
| 116 | 4 | PayloadLength | |
| 120 | n | Payload | |

`MessageId` is written Java-style: the two 64-bit halves of the UUID are
swapped relative to RFC 4122. Getting this wrong makes every acknowledgement
unmatchable and the session hang silently.

`PayloadDigest` is verified on receive. Exempt: zero-length payloads, and
`start_publication` / `pause_publication` (`ClientMessage.Validate` returns
early for those two message types). The serializer always writes a digest,
including SHA-256 of an empty payload; only validation is exempt.

`HeaderLength` is serialized as 116 by the reference plugin. This shard
rejects any other value instead of trusting it as an offset.

## Message types

| Type | Direction | Meaning |
|---|---|---|
| `input_stream_data` | client -> agent | input bytes, control payloads |
| `output_stream_data` | agent -> client | output, handshake, exit code |
| `acknowledge` | both | confirms one sequence number |
| `channel_closed` | agent -> client | session over; JSON body has `Output` |
| `start_publication` | gateway -> client | may start sending |
| `pause_publication` | gateway -> client | stop sending |

## Payload types

| # | Name | Encrypted with KMS |
|---|---|---|
| 0 | Undefined | - |
| 1 | Output | yes |
| 2 | Error | - |
| 3 | Size | - |
| 4 | Parameter | - |
| 5 | HandshakeRequest | no |
| 6 | HandshakeResponse | no |
| 7 | HandshakeComplete | no |
| 8 | EncChallengeRequest | no |
| 9 | EncChallengeResponse | no |
| 10 | Flag | - |
| 11 | StdErr | yes |
| 12 | ExitCode | yes |

## Reliability

- One outbound sequence counter shared by input data, terminal size, handshake
  response and encryption challenge response; allocate + record + enqueue under
  one lock.
- Only the head of the outbound queue is retransmitted (the agent is strictly
  in-order).
- Ack header: `SequenceNumber = 0`, `Flags = SYN | FIN`; the acknowledged
  sequence lives in the JSON payload:
  `{"AcknowledgedMessageType":..., "AcknowledgedMessageId":..., "AcknowledgedMessageSequenceNumber":..., "IsSequentialMessage":true}`.
- Inbound: `seq == expected` deliver+ack; `seq > expected` buffer+ack;
  `seq < expected` drop without acking.
- Chunking: 1024-byte input payloads by default (config), configurable.
- Liveness: ping every 30s, idle deadline on any inbound frame (120s default).
- Timers: retransmit scan 100ms, initial RTO 200ms, Jacobson/Karels clamped
  50ms..30s, give up after 3000 attempts, 10k-message buffers.

## Handshake payloads

```json
// HandshakeRequest (agent -> client, payload 5)
{"AgentVersion":"...","RequestedClientActions":[{"ActionType":"SessionType","ActionParameters":{...}}]}

// HandshakeResponse (client -> agent, payload 6)
{"ClientVersion":"1.0.0","ProcessedClientActions":[{"ActionType":"SessionType","ActionStatus":1,"ActionResult":null,"Error":""}],"Errors":[]}

// HandshakeComplete (agent -> client, payload 7)
{"HandshakeTimeToComplete":12345678,"CustomerMessage":""}
```

`ActionStatus`: Success = 1, Failed = 2, Unsupported = 3. The field is a
JSON number, not a name. `ActionResult` and `Errors` are `null` on success
(Go nil slice/interface), and `Error` is present as `""` on every processed
action. `Authorization` is signed before the `Connection`, `Upgrade` and
`Sec-WebSocket-*` headers are added, so `SignedHeaders` is exactly
`host;x-amz-date` plus `x-amz-security-token` when a token exists.

Divergence: for an unknown action the reference plugin's default branch sets
`ActionResult` to `Unsupported` and leaves `ActionStatus` at 0 (a bug); this
shard sets `ActionStatus = 3` and leaves `ActionResult` null, which is what the
agent actually checks.

Non-handshake output payloads: type 1 is stdout, type 11 is stderr, type 12 is
the ASCII text `EXIT_CODE: <n>` (from the agent's `sendExitCode`), and
`channel_closed.Output` is the session's closing text.

## Resume

`Reconnect` in the reference plugin calls `Close` then `Open` (which re-sends
the open token message) and does **not** reinitialize the data channel:
expected/outbound sequence numbers, buffers and encryption state survive, and
the agent handshake is not replayed. `ResumeSession` supplies a fresh
`StreamUrl`/`TokenValue` for the same session. This shard's
`Session#resume` follows that sequence, and the fake gateway's resume spec
asserts the open message carries the new token.

## KMS session encryption

1. Agent requests `KMSEncryption` with `{"KMSKeyId":"..."}`.
2. Client calls KMS `GenerateDataKey` with `NumberOfBytes: 64` and encryption
   context `{"aws:ssm:SessionId":..., "aws:ssm:TargetId":...}`.
3. Action result must mirror the plugin JSON exactly:
   `{"KMSCipherTextKey":"<base64>","KMSCipherTextHash":null}` (both fields are
   `[]byte` on the Go side; only the key is set).
4. `EncChallengeRequest` / `EncChallengeResponse` carry `Challenge` (base64 of
   Go `[]byte`) - not `ChallengeEnc`. The response is the request's challenge
   decrypted with the inbound key and re-encrypted with the outbound key.
5. AES-256-GCM per message: 12-byte random nonce prepended to the ciphertext;
   the first 32 bytes of the 64-byte key decrypt inbound, the last 32 encrypt
   outbound (agent mirrors).
6. Failure to negotiate must never downgrade to plaintext.

## Pin list status

Pinned by phase 1-4 specs:

- Header constants, offsets, `MessageType` space padding and digest exemptions
  (`clientmessage.go` / `messageparser.go`).
- `MessageId` byte order, both directions, with hand-written bytes.
- Ack `Flags = SYN | FIN`, sequence 0, and the payload JSON shape.
- Timer defaults from `src/config/config.go`.
- `Size` (payload 3): acknowledged and ignored (decision above).
- Handshake request/response/complete JSON shapes, including `ActionResult:
  null`, `Errors: null`, numeric `ActionStatus`, and nanosecond
  `HandshakeTimeToComplete`.
- `ResumeSession` state replay (decision above).

Still to pin in phase 5:

- KMS `GenerateDataKey` request shape, `KMSCipherTextKey` / `KMSCipherTextHash`
  JSON, the `Challenge` decrypt->re-encrypt transform, and AES-256-GCM vectors.
