require "../spec_helper"

# Live tests need a real SSM-managed target and real credentials. They are
# opt-in and never run in CI:
#
#   KRIKRI_SSM_LIVE=1 SSM_TARGET=i-... SSM_REGION=us-east-2 just live
describe "live SSM (opt-in)" do
  it "is skipped unless KRIKRI_SSM_LIVE=1" do
    if ENV["KRIKRI_SSM_LIVE"]? == "1"
      # The live suite lands with the session implementation (shell exec,
      # file transfer, KMS-encrypted session, reconnect).
      assert true
    end
  end
end
