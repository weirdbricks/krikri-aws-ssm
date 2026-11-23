# Changelog

## 0.4.2 (2026-11-22)

- Distinguish a GCM authentication failure from a cipher setup failure in
  `Encrypter#decrypt`, so a provider/configuration error is not reported as
  "failed authentication".
- Specs: an empty-payload encryption round trip, a black-holed connect that
  must become a `HandshakeFailed` within the budget, concurrent
  `Client#credentials` callers resolving once, and the container timeout
  applied to a slow remote `FULL_URI`.

## 0.4.1 (2026-11-22)

Follow-up to 0.4.0, closing the remaining review items.

- Ping failures now close the session as `NetworkLost` instead of waiting for
  the idle deadline; the handshake request is processed off the reader fiber
  so a slow `GenerateDataKey` does not stop acknowledgements/pings, and an
  already-owned output payload is no longer copied a second time.
- `Message#payload_digest` always reflects the current payload, and `encode`
  rejects a message type that decode would not reproduce (NUL or edge
  whitespace). Decode-only handshake structs now emit nulls like the
  reference.
- KMS rejects a non-string `KeyId`; SSO rejects a key that disagrees between
  a profile and its `sso-session` and names the keys missing from a
  half-configured SSO profile; the shared config is parsed once per chain
  (botocore session semantics); IMDS reuses one keep-alive client for its
  token and GETs; container retries use a configurable backoff.
- The fake gateway verifies presigned upgrades (signature present, no
  Authorization), verifies SigV4 in a configurable region, and its request
  channels no longer stall a busy spec. Specs close the remaining gaps:
  expiry boundaries, cache hits, resume output delivery, concurrent state
  reads, KMS base64/KeyId failures and container retries.

## 0.4.0 (2026-11-22)

Review hardening (no public API removals).

- Redact `inspect` on `SessionInfo`, `Credentials`, `Settings`, `Session` and
  `Kms::DataKey`; it printed every ivar (session tokens, signed stream URLs,
  secret keys) where only `to_s` was redacted.
- Treat a non-object JSON body as a typed `ProtocolError`/`ApiError` instead
  of letting `JSON::Any#[]?` raise a bare `Exception`; the encryption
  challenge path now fails the handshake rather than killing the reader fiber.
- Widen the frame-size check to `Int64`, so a hostile `PayloadLength` raises
  `ProtocolError` instead of `OverflowError`.
- Bound the data-channel dial: `connect_timeout` on the TCP connect and
  `read_timeout` for the TLS/upgrade read, cleared once the channel is up.
- Sign control-plane and KMS calls with refreshed credentials instead of the
  snapshot taken at construction; one credential read per dial; serialize
  `Client#credentials`.
- Bound the credential cache: one superseded value per profile, one provider
  call for concurrent refreshes, and unknown credentials returned unchanged
  instead of resolving another profile's keys.
- Generation-guard resume: stale frames, sends and closes cannot touch the
  resumed session; a failed resume re-closes instead of leaving it half open;
  an explicit `terminate` always calls `TerminateSession`, even after
  `NetworkLost`.
- Drive liveness from progress (deliveries and meaningful acknowledgements),
  close a gap that does not heal within `idle_timeout` with `ProtocolError`,
  and meter buffered out-of-order frames against `output_buffer_limit`.
- Synchronize the session state read across fibers; wipe the KMS data key on
  close; acknowledge frames after processing them, track outbound frames
  before sending, and replace a buffered retransmit instead of overflowing.
- Credentials parity: IMDSv1 fallback with `AWS_EC2_METADATA_V1_DISABLED`,
  IMDS endpoint/mode/attempts knobs, the EKS Pod Identity plain-http
  allow-list, ECS query strings, file-first authorization tokens with
  line-break rejection, 2 s/3-attempt container timeouts, SSO token refresh,
  retries for DNS/TLS/throttling, the China partition, `:reason` error-code
  normalization, empty env values as unset, and a named partial-credentials
  error. A hung MFA prompt now times out instead of holding the chain mutex.
- Docs/toolchain: protocol.md send window and liveness text corrected, README
  and 1664-plan phase/version drift fixed, `Time.monotonic` migrated to
  `Time.instant`, `spec/live` added to the `just test` build, and `.crush/`
  ignored.

## 0.3.0 (2026-11-22)

- Add `Session#write_raw`, a binary-safe write that skips `write`'s
  reference-plugin LF-to-CR rewrite. Callers moving a binary protocol through a
  pty (krikri's `synchronize:` bridge) must not have a chunk that happens to be
  a single LF turned into CR. Specs pin both behaviours.
- Fix the test agent dropping its last two frames when a shell exits: it closed
  the websocket immediately after sending `ExitCode` + `ChannelClosed`, and the
  client saw the transport drop first, losing the exit status and the close
  reason. It now leaves the shutdown to the client after `ChannelClosed`, as a
  real agent does.

## 0.2.3 (2026-11-21)

- Support MFA-token AssumeRole (issue #1696): a profile with `role_arn` and
  `mfa_serial` now prompts for the one-time code on the terminal (echo
  suppressed when `stty` allows it) and sends `SerialNumber` + `TokenCode`
  with AssumeRole. Non-interactive callers can inject
  `CredentialChain::Config#mfa_token_provider`; when neither a terminal nor a
  provider is available the chain fails with a clear error instead of guessing.
  Terminal prompts are serialized across concurrent sessions, and the code is
  never logged. A credential refresh prompts again rather than raising as
  botocore does (`RefreshWithMFAUnsupportedError`); that divergence is
  deliberate, so a provider can supply the fresh single-use code.

## 0.2.2 (2026-11-21)

- Fix the sustained-upload collapse behind issue #1692. Measured on a live
  agent (3.3.5828.0): a burst at the reference 10,000-message depth overruns
  the agent's input path, the service drops messages, and the stream drains at
  ~25 KiB/s because only the queue head is retransmitted (one message per
  scan). The send window is now 64 KiB of in-flight encoded bytes
  (`Settings#send_window_bytes`), which keeps every message inside the agent's
  receive path: a 4 MiB payload in 5.59 MB of base64 went from 199.1 s
  (27 KiB/s) to 5.8 s (939 KiB/s) on a t3a.micro. `TCP_NODELAY` is also set
  (Go and the reference plugin do), though measured to make no difference once
  the window paces the sender; `Settings#tcp_nodelay` allows an A/B run.
- Replace the bounded output channel with a growable queue: the websocket
  reader never waits for a caller to read output, so acknowledgements keep
  flowing while a bulk upload is in progress. `Settings#output_buffer_limit`
  caps the memory and a new `OutputBufferExceeded` error fails an unread
  session instead of blocking it.
- The send window waits for acknowledgements instead of dropping the oldest
  unacknowledged message at the reference plugin's 10,000-message capacity
  (dropping the head abandons a sequence the agent is still waiting for).
  `Settings#send_window_bytes` sets the window, and an ack-stalled stream
  closes with `SessionTimeout` after `idle_timeout` instead of blocking a
  writer for the whole retransmission budget.
- Pings are serialized with data writes, and `close!` snapshots the connection
  it is tearing down, so a `resume` racing with a drop cannot have its new
  websocket or output queue closed by the old teardown.
- Add `Session#stats`, a diagnostic snapshot of the outbound channel
  (messages, bytes, acks/second, pending messages and bytes, peak pending,
  ack idle, retransmissions and round-trip percentiles), and an opt-in live
  test that pins the sustained rate of a multi-megabyte upload and prints
  those counters.

## 0.2.1 (2026-11-21)

- Keep SSM input flowing on a real agent: `pause_publication` and
  `start_publication` are advisory (matching the reference plugin), output is
  buffered so the websocket reader keeps processing acknowledgements while a
  caller is not reading, the retransmission timeout caps at one second, and the
  outgoing retransmit buffer drops its oldest entry at the reference plugin's
  10,000-message capacity instead of growing without bound.

## 0.2.0 (2026-11-21)

- Phase 5: KMS session encryption. `Kms` calls `GenerateDataKey` (64 bytes,
  encryption context `aws:ssm:SessionId`/`aws:ssm:TargetId`), the handshake
  action returns the plugin's exact `{"KMSCipherTextKey":...,"KMSCipherTextHash":null}`
  result, `EncChallengeRequest` is decrypted and re-encrypted with the split
  key, and payload types 1/11/12 use AES-256-GCM with a 12-byte nonce. A KMS
  denial fails the handshake instead of downgrading to plaintext.
- Phase 6: the standard AWS credential chain: environment statics, environment
  web identity (IRSA), shared profiles (`credential_process`, `role_arn` +
  `source_profile`/`credential_source`, `web_identity_token_file`, SSO), ECS
  container credentials and IMDSv2, with expiry-aware refresh.
- Phase 7: real-account validation harness (`terraform/`) and an opt-in live
  suite covering command execution, KMS-encrypted sessions, a 1 MiB round trip
  and `TerminateSession` cleanup, plus a real `AssumeRole` profile.
- Fake harness for downstream (krikri) integration tests: the
  `require "krikri-aws-ssm/testing"` entrypoint now exists, the agent's pty
  shell accepts extra environment through `FakeAgent::Options#shell_env`,
  `FakeGateway#control_failure` answers every control-plane action with a
  chosen status and body so a spec can pin the client's error mapping, and
  `FakeGateway#next_upgrade_result` gives a timed, non-destructive wait for
  the verified signed-header set. Observation channels drop samples when
  nothing drains them instead of blocking the agent's websocket reader, so
  multi-megabyte transfers complete in-process.
- The krikri SSM transport (phase 8) and its in-process test matrix live in
  `krikri-playbook`; this release ships the harness entrypoint they use.

## 0.1.0

- Initial scaffold: shard metadata, CI, formatting/lint baseline, provenance
  NOTICE, and the wire-protocol notes in `docs/protocol.md`.
- Phase 1: Java-order UUID codec, the 120-byte message codec with digest
  validation, and all message/payload/flag constants pinned from
  `aws/session-manager-plugin`.
- Phase 2: in-process SigV4-verifying fake gateway, fake agent with a real pty
  shell, pty binding, and integration scenarios (handshake, stdout/stderr,
  chunking, retransmission, pause/publication backpressure, 1MiB round trip,
  presigned URLs, reconnect).
- Phase 3: signed JSON-1.1 client for StartSession, ResumeSession,
  TerminateSession and DescribeSessions, endpoint override, typed error
  mapping and connection-establishment retries.
- Phase 4: session core - manual signed websocket upgrade (exact Host header),
  open token message, agent handshake, input chunking, ordered inbound
  delivery with acks, retransmission with Jacobson/Karels RTO, liveness pings,
  idle timeout, and ResumeSession reconnect.
