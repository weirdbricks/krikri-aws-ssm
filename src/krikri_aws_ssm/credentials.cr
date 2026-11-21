# The AWS credential chain: environment statics, environment web identity
# (IRSA), shared profile/config (static keys, `credential_process`,
# `role_arn` + `source_profile`/`credential_source`, web identity, SSO), ECS
# container metadata, then IMDSv2.
#
# `credential_process` executes the command configured in the AWS profile with
# `sh -c` and parses its JSON output; the command is trusted configuration and
# its stdout is never logged.
#
# Provenance: provider ordering, profile/config merging, SSO token cache
# naming and error text are pinned from botocore (`botocore.credentials`,
# `botocore.utils.SSOTokenLoader`, Apache-2.0). The STS and SSO wire formats
# follow the services' published APIs.
require "./errors"
require "./credentials/types"
require "./credentials/transport"
require "./credentials/config"
require "./credentials/profile"
require "./credentials/sts"
require "./credentials/sso"
require "./credentials/imds"
require "./credentials/ecs"
require "./credentials/chain"
