# SSM Session Manager wire protocol (working notes)

Status: working spec transcribed from the reference implementations. Every
constant below is pinned by specs taken from the sources - nothing here may
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
- The dial bounds connect (`connect_timeout`) and the TLS/upgrade read
  (`read_timeout`); the established channel is long-lived and is paced by the
  ping/idle loops instead.
- Trust assumption: the peer is the AWS service and its agent over TLS, so the
  websocket layer does not cap a single message's size before the frame parser
  runs (Crystal's `HTTP::WebSocket::Protocol` allocates from the declared
  length). A compromised agent could therefore force a large allocation before
  the SSM frame parser sees the message; that parser still rejects a payload
  length that disagrees with the frame.
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
| `start_publication` | gateway -> client | advisory resume hint |
| `pause_publication` | gateway -> client | advisory pause hint |

`start_publication` and `pause_publication` are **not** meaningful flow control
for the client: the reference plugin's `OutputMessageHandler`
(`src/datachannel/streaming.go`) returns nil for both and keeps writing.
Honouring them throttled a live session's input to roughly 30 KiB/s (one
1024-byte message per round trip), so this shard accepts and ignores both.
Real backpressure is the agent's acknowledgement stream, applied through the
send window above and never by blocking this reader.

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
- Inbound: `seq == expected` processes the frame then acks it; `seq >
  expected` buffers and acks it; `seq < expected` drops it without acking.
  Buffered frames are metered against `output_buffer_limit`, and a gap that
  does not heal within `idle_timeout` closes with `ProtocolError` instead of
  waiting for traffic to stop.
- Chunking: 1024-byte input payloads by default (config), configurable.
- Liveness: ping every 30s; the idle deadline (120s default) runs on
  *progress* - a delivered frame or an acknowledgement of one of our
  messages - not on raw inbound bytes, so a peer that keeps retransmitting
  buffered or duplicate frames cannot mask a wedged sequencer.
- Timers: retransmit scan 100ms and initial RTO 200ms (`ResendSleepInterval`,
  `DefaultTransmissionTimeout`), give up after 3000 attempts
  (`ResendMaxAttempt`). Jacobson/Karels uses the plugin's 1s cap
  (`MaxTransmissionTimeout`); the 50ms floor is the bridge's, not the
  plugin's (the plugin floors only at `ClockGranularity`, 10ms).
- Send window: a writer waits for acknowledgements once 64 KiB of encoded
  frames are unacknowledged (`Settings#send_window_bytes`; measured, see the
  Throughput section). The reference plugin instead bounds by
  `OutgoingMessageBufferCapacity` and drops the oldest unacknowledged entry
  (`AddDataToOutgoingMessageBuffer` in `src/datachannel/streaming.go`), which
  abandons a sequence the agent is still waiting for and can stall the stream;
  `aws-ssm-bridge` documents the same divergence. A stream with no
  acknowledgement for `idle_timeout` closes with `SessionTimeout` so the
  waiting writer cannot hang indefinitely.
- Inbound RTT samples skip retransmitted messages (Karn's algorithm), so a
  retransmission storm does not masquerade as a huge round trip. Divergence:
  the reference plugin samples every acknowledgement, including retransmitted
  ones.

## Throughput

The data channel is TCP/TLS, so the client's send path decides how fast a bulk
upload leaves the controller. The limiting mechanism is not TCP flow control
but the agent's input path: a burst larger than it can absorb is dropped by
the service, and because only the queue head is retransmitted, recovery costs
one round trip per lost message.

Measured on a live t3a.micro (Amazon Linux 2023, agent 3.3.5828.0,
KMS-encrypted session, ~60ms RTT), uploading the base64 of a 4 MiB payload
(5.59 MB, 5,593 messages):

| In-flight send window | Wall time | Effective rate | Retransmissions |
|---|---:|---:|---:|
| 10,000 messages / 16 MB (reference buffer depth) | 199.1 s | 27 KiB/s | 1,816 |
| 256 messages (~280 KB) | 27.4 s | 204 KiB/s | 257 |
| 128 messages (~140 KB) | 11.4 s | 490 KiB/s | 97 |
| 64 KiB (`Settings#send_window_bytes` default) | 5.8 s | 939 KiB/s | 0 |
| 48 messages (~53 KB) | 7.2 s | 776 KiB/s | 1 |

With the big window the first ~3.8 MB is accepted at ~1,300 messages/s, then
the service starts dropping and the remaining backlog drains at ~10 messages/s
(one per retransmit scan) - the ~30 KiB/s collapse from issue #1692. A window
of 64 KiB of encoded frames keeps every message inside the agent's receive
path and sustains ~0.9 MiB/s; the send-window default is therefore
`Settings#send_window_bytes = 64 KiB`, not the reference plugin's
`OutgoingMessageBufferCapacity`.

- `TCP_NODELAY` is still set (Go's `net` package, and therefore the reference
  plugin, disables Nagle by default; Crystal's `TCPSocket` does not). Measured
  at a 64 KiB window, on/off made no difference (5.5 s vs 5.9 s); it is not the
  throughput fix, but it is the correct setting for a websocket client.
  `Settings#tcp_nodelay` allows an A/B run.
- Write coalescing is not a lever: `OpenSSL::SSL::Socket` is already buffered
  and the websocket protocol flushes at the end of every frame, so a `wss`
  frame reaches `SSL_write` as one write.
- Larger chunks do not help: `aws-ssm-bridge`'s published wire notes report
  8 KiB and 32 KiB chunks accepted by a live agent (3.3.3572.0) and performing
  identically. The 1024-byte default is kept for interoperability and is
  configurable through `Settings#chunk_size`.
- Unread output never blocks the websocket reader. A bounded queue stopped
  acknowledgement processing whenever output was not drained (and deadlocked
  an upload whose writer waited for acks). Output is buffered in a growable
  queue bounded by `Settings#output_buffer_limit`; exceeding it closes the
  session with `OutputBufferExceeded`.

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

Pinned by the protocol and session specs:

- Header constants, offsets, `MessageType` space padding and digest exemptions
  (`clientmessage.go` / `messageparser.go`).
- `MessageId` byte order, both directions, with hand-written bytes.
- Ack `Flags = SYN | FIN`, sequence 0, and the payload JSON shape.
- Timer defaults from `src/config/config.go`.
- `Size` (payload 3): acknowledged and ignored (decision above).
- Send window of 64 KiB in flight (measured; issue #1692), the ack-stall
  close, Karn's algorithm for RTT samples (a labeled divergence),
  `TCP_NODELAY`, and a growable output queue that never blocks the reader.
- Handshake request/response/complete JSON shapes, including `ActionResult:
  null`, `Errors: null`, numeric `ActionStatus`, and nanosecond
  `HandshakeTimeToComplete`.
- `ResumeSession` state replay (decision above).

Pinned by the KMS and encryption specs:

- KMS `GenerateDataKey` request shape (`NumberOfBytes: 64`, encryption context
  `aws:ssm:SessionId` / `aws:ssm:TargetId`) and the exact action result JSON
  `{"KMSCipherTextKey":"<base64>","KMSCipherTextHash":null}`.
- The `Challenge` decrypt-with-inbound-key / re-encrypt-with-outbound-key
  transform, both directions, against the fake agent.
- AES-256-GCM layout (12-byte nonce, ciphertext, 16-byte tag), the first-half
  decrypt / last-half encrypt split, and a vector generated by an independent
  implementation (Python `cryptography`, not Crystal's OpenSSL binding).
- Failure of `GenerateDataKey` (for example `AccessDeniedException`) fails the
  handshake with the action marked `Failed`; it never downgrades to plaintext.
