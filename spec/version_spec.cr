require "./spec_helper"

describe KrikriSSM do
  it "exposes the shard version" do
    assert_equal "0.1.0", KrikriSSM::VERSION
  end
end
