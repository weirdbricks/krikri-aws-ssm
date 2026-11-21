# Changelog

## 0.1.0 (in development)

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
- Still planned for 0.1.0: KMS session encryption and the full credential chain
  (profiles, assume-role, SSO, IMDSv2, ECS/IRSA, credential_process). KMS
  requests currently fail the handshake rather than downgrade to plaintext.
