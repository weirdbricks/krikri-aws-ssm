require "./spec_helper"

describe KrikriAwsSsm::Settings do
  it "never reveals credentials from to_s or inspect" do
    settings = KrikriAwsSsm::Settings.new("i-0123456789",
      credentials: KrikriAwsSsm::Credentials.new("AKIDEXAMPLE", "super-secret", "session-token"))

    [settings.to_s, settings.inspect].each do |text|
      refute_includes text, "super-secret"
      refute_includes text, "session-token"
      assert_includes text, "i-0123456789"
    end
  end
end
