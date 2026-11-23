abs_spec_bin := justfile_directory() + "/.crystal-build-cache/spec_bin"

# Run the spec suite in parallel across 4 OS threads.
#
# The parallel execution context is the default on current Crystal, so no
# -Dpreview_mt is needed (and that deprecated flag must not come back: on 1.22 it
# makes concurrent access to shared mutable state return stale values).
test: build-spec
    CRYSTAL_WORKERS=4 {{abs_spec_bin}} --parallel 4

# Single-threaded run - use this to bisect whether a failure is a real bug or a
# parallel-run race.
test-serial:
    crystal spec

build-spec:
    mkdir -p .crystal-build-cache
    crystal build spec/spec_helper.cr spec/*_spec.cr spec/live/*_spec.cr -o {{abs_spec_bin}}

# Formatting and lint.
format:
    crystal tool format src spec

lint:
    crystal tool format src spec --check
    crystal lib/ameba/bin/ameba.cr

# Live tests against a real SSM target. Never run in CI.
#   KRIKRI_SSM_LIVE=1 SSM_TARGET=i-... SSM_REGION=us-east-2 just live
live:
    KRIKRI_SSM_LIVE=1 crystal spec spec/live
