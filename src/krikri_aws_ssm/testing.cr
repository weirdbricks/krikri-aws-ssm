# Test harness shared by this shard's specs and krikri's in-process SSM
# integration tests. Not required by `src/krikri-aws-ssm.cr`, so the runtime
# library stays free of test-only code.
require "./testing/pty"
require "./testing/sigv4_verifier"
require "./testing/fake_agent"
require "./testing/fake_gateway"
