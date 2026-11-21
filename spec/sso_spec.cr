require "./spec_helper"
require "./support/credentials_helper"

include CredentialSpecHelper

private def write_sso_token(dir : String, key : String, access_token : String,
                            expires_at : Time = Time.utc + 1.hour) : String
  path = File.join(dir, "sso-cache", "#{Digest::SHA1.hexdigest(key)}.json")
  CredentialSpecHelper.write(path, JSON.build do |json|
    json.object do
      json.field "accessToken", access_token
      json.field "expiresAt", expires_at.to_s("%Y-%m-%dT%H:%M:%SZ")
      json.field "startUrl", key
      json.field "region", "us-east-1"
    end
  end)
end

describe KrikriAwsSsm::CredentialChain::Sso do
  it "reads the cached token and calls GetRoleCredentials with a bearer header" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sso_response)
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        start_url = "https://example.awsapps.com/start"
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile sso]
          sso_start_url = #{start_url}
          sso_region = us-east-1
          sso_account_id = 123456789012
          sso_role_name = MyRole
          INI
        write_sso_token(dir, start_url, "bearer-token")

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sso_endpoint: server.url)
        credentials = chain.resolve("sso")

        assert_equal "SSOKEY", credentials.access_key
        assert_equal "SSOSECRET", credentials.secret_key
        assert_equal "SSOTOKEN", credentials.session_token
        assert credentials.expires_at

        request = server.next_request
        assert_equal "GET", request.method
        uri = URI.parse(request.resource)
        assert_equal "/federation/credentials", uri.path
        params = URI::Params.parse(uri.query.to_s)
        assert_equal "MyRole", params["role_name"]
        assert_equal "123456789012", params["account_id"]
        assert_equal "bearer-token", request.headers["x-amz-sso_bearer_token"]
        assert_nil request.headers["Authorization"]?

        assert_equal Digest::SHA1.hexdigest(start_url),
          KrikriAwsSsm::CredentialChain::Sso.cache_key(start_url)
      end
    ensure
      server.close
    end
  end

  it "names the token cache by sso-session name when the profile uses sso_session" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sso_response)
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        start_url = "https://example.awsapps.com/start"
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [sso-session my-sso]
          sso_start_url = #{start_url}
          sso_region = us-east-1
          sso_registration_scopes = sso:account:access

          [profile sso]
          sso_session = my-sso
          sso_account_id = 123456789012
          sso_role_name = MyRole
          INI
        # A decoy file keyed by the start URL must not be used.
        write_sso_token(dir, start_url, "wrong-token")
        write_sso_token(dir, "my-sso", "session-token")

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sso_endpoint: server.url)
        chain.resolve("sso")

        assert_equal "session-token", server.next_request.headers["x-amz-sso_bearer_token"]
        assert_equal Digest::SHA1.hexdigest("my-sso"),
          KrikriAwsSsm::CredentialChain::Sso.cache_key(start_url, "my-sso")
      end
    ensure
      server.close
    end
  end

  it "raises the parity error for an expired SSO token" do
    CredentialSpecHelper.with_temp_dir do |dir|
      start_url = "https://example.awsapps.com/start"
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile sso]
        sso_start_url = #{start_url}
        sso_region = us-east-1
        sso_account_id = 123456789012
        sso_role_name = MyRole
        INI
      write_sso_token(dir, start_url, "expired-token", Time.utc - 1.minute)

      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("sso") }
      assert_equal "The SSO session associated with this profile has expired or is invalid. " \
                   "Please run aws sso login",
        error.message
    end
  end

  it "names the profile when the SSO token cache entry is missing" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile sso]
        sso_start_url = https://example.awsapps.com/start
        sso_region = us-east-1
        sso_account_id = 123456789012
        sso_role_name = MyRole
        INI
      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("sso") }
      assert_includes error.message.to_s, "sso"
      assert_includes error.message.to_s,
        "The SSO session associated with this profile has expired or is invalid. " \
        "Please run aws sso login"
    end
  end

  it "turns an unauthorized GetRoleCredentials response into the parity error" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(401, %({"message":"expired"}))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        start_url = "https://example.awsapps.com/start"
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile sso]
          sso_start_url = #{start_url}
          sso_region = us-east-1
          sso_account_id = 123456789012
          sso_role_name = MyRole
          INI
        write_sso_token(dir, start_url, "stale-token")

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sso_endpoint: server.url)
        error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("sso") }
        assert_equal "The SSO session associated with this profile has expired or is invalid. " \
                     "Please run aws sso login",
          error.message
      end
    ensure
      server.close
    end
  end
end
