require "./spec_helper"

describe KrikriAwsSsm do
  it "exposes the shard version" do
    assert_equal "1.0.1", KrikriAwsSsm::VERSION
  end
end
