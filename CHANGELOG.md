# Changelog

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
