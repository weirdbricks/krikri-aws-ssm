# AGENTS.md

Guidance for AI agents (and humans) working in this repository.

## What this project is

**krikri-aws-ssm** is a native AWS Systems Manager (SSM) Session Manager client in
pure Crystal. It exists so
[`krikri-playbook`](https://github.com/weirdbricks/krikri) can run playbooks
against SSM-only fleets with the equivalent of Ansible's
`amazon.aws.aws_ssm` connection - without an S3 bucket, the AWS CLI, or
`session-manager-plugin`.

It is a byte-stream session library: `StartSession`/`ResumeSession`/
`TerminateSession`, the data-channel wire protocol, KMS session encryption, and
the AWS credential chain. The Ansible-shaped parts (marker-based shell, pty
terminal setup, base64 file transfer, become wrappers, error text, batching)
belong in krikri, not here. Keep the boundary strict: krikri must be able to
consume this shard without pulling Ansible semantics into it.

## Commands

```sh
shards install                       # needed once before specs/ameba
crystal spec                         # full test suite (minitest.cr)
just test                            # spec suite, 4 OS threads
just test-serial                     # single-threaded (bisect parallel races)
crystal spec spec/message_spec.cr    # one file
crystal tool format src spec --check # formatting (run without --check to fix)
crystal lib/ameba/bin/ameba.cr       # lint
```

The parallel execution context is the default on current Crystal, so nothing
needs `-Dpreview_mt` - that flag is deprecated and must not be reintroduced.

CI (`.github/workflows/ci.yml`) runs format + ameba on
`crystallang/crystal:1.22.2-alpine` and `crystal spec` on 1.22.2 and 1.13.0.

## Provenance (non-negotiable)

AWS publishes only the control-plane API; the data-channel wire format is
defined by the Apache-2.0 reference implementations. This project is a
**derivative**, not clean-room. See `NOTICE`.

- Every protocol constant, field name, byte order, timer and JSON shape must be
  pinned from a reference implementation or its published "documented by
  observation" notes - never from this shard's own output.
- `docs/protocol.md` is the maintained local spec. Update it in the same commit
  as any protocol change.
- When logic is transliterated from an Apache-2.0 source, add a per-file
  provenance note and include the Apache-2.0 text if the license requires it.

## Security rules

- The session token travels only in the data-channel open message - never in a
  URL, argv, or a log line. Redact `TokenValue` and `StreamUrl` everywhere.
- Verify payload SHA-256 digests and KMS GCM tags; reject mismatches.
- Refuse non-TLS data-channel endpoints except when an explicit test endpoint
  is configured (integration tests use `ws://127.0.0.1`).
- Never write credentials or session tokens into fixtures, logs or commits.

## Dependencies

Runtime: Crystal stdlib plus `krikri-aws-signer` (SigV4). No new runtime
dependencies without a strong reason; the zero-AWS-SDK property is the point.
Dev: `ameba` 1.7.0 (the exact version krikri uses; lint is part of CI and the
`just lint` target, and no `# ameba:disable` annotations without a comment
explaining why) and the `weirdbricks/minitest.cr` fork, pinned to
`v1.7.0-weirdbricks.2` like krikri and `krikri-aws-signer`.

## Release

- Bump `version` in `shard.yml` and `CHANGELOG.md` per logical change.
- Tag `vX.Y.Z`, push, then krikri pins the tag in its `shard.yml` and runs
  `shards update krikri-aws-ssm` (same workflow as `krikri-jinja`).
- Live validation is a release gate for protocol changes: run
  `KRIKRI_SSM_LIVE=1 SSM_TARGET=i-... SSM_REGION=... just live` against a real
  target, including an encrypted session when the account mandates it.
