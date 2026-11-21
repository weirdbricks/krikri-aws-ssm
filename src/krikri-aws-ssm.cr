# Native AWS Systems Manager (SSM) Session Manager client in pure Crystal.
#
# This shard speaks the Session Manager data-channel protocol itself, so a
# controller needs neither the AWS CLI nor `session-manager-plugin`. The
# Ansible-shaped parts (marker-based shell, pty setup, base64 file transfer,
# become wrappers, error text) live in krikri-playbook, not here.
#
# See `docs/protocol.md` for the wire format and `NOTICE` for provenance.
require "./krikri_aws_ssm/errors"
require "./krikri_aws_ssm/payload"
require "./krikri_aws_ssm/uuid"
require "./krikri_aws_ssm/message"

module KrikriAwsSsm
  VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify }}
end
