# krikri-aws-ssm

Native AWS Systems Manager (SSM) Session Manager client in pure Crystal, for
[`krikri-playbook`](https://github.com/weirdbricks/krikri). It speaks the SSM
data-channel protocol itself, so the controller needs **no AWS CLI** and **no
`session-manager-plugin`** - only the SSM agent on the target and the usual AWS
permissions.

Status: phases 1-8 complete (wire protocol and session core, fake harness,
control plane, KMS encryption, credential chain, live validation, and the
krikri SSM transport). The remaining krikri wiring and its test matrix
(phases 9-10) live in krikri-playbook. See `docs/protocol.md` for the wire
format and the design notes it is built from.

## What it does

- `ssm:StartSession` / `ResumeSession` / `TerminateSession`, SigV4-signed
  (JSON 1.1), with an endpoint override.
- The Session Manager data channel: 120-byte binary framing, handshake,
  sequenced input/output with acknowledgements and retransmission, liveness.
- KMS session encryption (accounts whose Session Manager preferences mandate
  it), AES-256-GCM.
- The standard AWS credential chain: environment, shared profiles
  (`credential_process`, `role_arn` + `source_profile` / `credential_source`,
  `web_identity_token_file`/IRSA), SSO cache + `sso:GetRoleCredentials`, IMDSv2,
  ECS container credentials.

It is a byte-stream session library: the Ansible-shaped shell protocol, file
transfer and error text live in krikri, not here.

## Not in scope

- The AWS CLI and `session-manager-plugin` (by design).
- S3 file staging (krikri moves bytes through the session itself).
- Port forwarding / smux, `AWS-StartSSHSession`, Windows sessions.
- MFA-token AssumeRole (planned follow-up).

## Requirements and permissions

- Controller: Crystal `>= 1.13.0`, egress to `ssm.<region>.amazonaws.com` and
  the data-channel host returned in `StreamUrl`.
- Target: SSM agent, registered as a managed node.
- Caller: `ssm:StartSession`, `ssm:ResumeSession`, `ssm:TerminateSession`, the
  `ssmmessages` channel actions, and `kms:GenerateDataKey` when sessions are
  encrypted (the target's instance profile needs `kms:Decrypt`).

## Usage (sketch)

```crystal
require "krikri-aws-ssm"

settings = KrikriAwsSsm::Settings.new(
  target: "i-0123456789abcdef0",
  region: "us-east-2",
)

session = KrikriAwsSsm::Session.open(settings)
session.write("printf 'hello\\n'\n".to_slice)
while output = session.read?
  print String.new(output.bytes)
end
session.terminate
```

The public API is being built out; see the specs for the current surface.

## Development

```sh
shards install
crystal spec                 # full suite
just test                    # parallel spec run
crystal tool format src spec --check
crystal lib/ameba/bin/ameba.cr
```

Live tests against a real SSM target are opt-in (`KRIKRI_SSM_LIVE=1`,
`SSM_TARGET`, `SSM_REGION`, optional `SSM_ASSUME_ROLE_ARN`) and never run in
CI. `terraform/` provisions the SSM-only AL2023 target, a KMS key whose
preferences document mandates encryption, and a role to assume; destroy it
after each validation round.

The throughput test streams `SSM_LIVE_SUSTAINED_BYTES` (4 MiB by default) and
fails below `SSM_LIVE_MIN_KIBPS` (64 KiB/s by default), printing
`Session#stats`: message and ack rates, peak pending, retransmissions and
round-trip percentiles. `SSM_LIVE_NO_NAGLE=1` reruns it without `TCP_NODELAY`
for an A/B against the pre-0.2.2 behaviour.

Downstream tests drive sessions in-process through the fake gateway/agent
harness: `require "krikri-aws-ssm/testing"`. `FakeAgent::Options#shell_env`
merges extra variables into the agent's pty shell (a stub `sudo`, a PATH), and
`FakeGateway#control_failure` answers every SSM control-plane action with a
given status and body. The gateway's getters are `Channel`s, which are Iterators
here: never poll them with `empty?` (it consumes a value and blocks on an empty
channel); use `FakeGateway#next_upgrade_result` or a `select`.

Development deps mirror krikri: `ameba` 1.7.0 and the
`weirdbricks/minitest.cr` fork (`v1.7.0-weirdbricks.2`).

## License and provenance

MIT (see `LICENSE`). This is a derivative of the open-source reference
implementations, not a clean-room project - see `NOTICE` for the sources and
attribution.
