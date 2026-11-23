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

  it "rejects a non-object SSO token cache entry with the parity error" do
    CredentialSpecHelper.with_temp_dir do |dir|
      start_url = "https://example.awsapps.com/start"
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile sso]
        sso_start_url = #{start_url}
        sso_region = us-east-1
        sso_account_id = 123456789012
        sso_role_name = MyRole
        INI
      CredentialSpecHelper.write(
        File.join(dir, "sso-cache", "#{Digest::SHA1.hexdigest(start_url)}.json"), %(["nope"]))

      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("sso") }
      assert_includes error.message.to_s, "not a JSON object"
    end
  end

  it "refreshes an expired cache with its refresh token before failing" do
    oidc_request : HTTP::Request? = nil
    portal_request : HTTP::Request? = nil
    transport = ->(request : HTTP::Request, endpoint : URI) do
      if endpoint.host.try(&.starts_with?("oidc."))
        oidc_request = request
        HTTP::Client::Response.new(200, %({"accessToken":"fresh-token","expiresIn":3600}))
      else
        portal_request = request
        HTTP::Client::Response.new(200, CredentialSpecHelper.sso_response)
      end
    end
    CredentialSpecHelper.with_temp_dir do |dir|
      start_url = "https://example.awsapps.com/start"
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile sso]
        sso_start_url = #{start_url}
        sso_region = us-east-1
        sso_account_id = 123456789012
        sso_role_name = MyRole
        INI
      path = File.join(dir, "sso-cache", "#{Digest::SHA1.hexdigest(start_url)}.json")
      CredentialSpecHelper.write(path, JSON.build do |json|
        json.object do
          json.field "accessToken", "expired-token"
          json.field "expiresAt", (Time.utc - 1.minute).to_s("%Y-%m-%dT%H:%M:%SZ")
          json.field "refreshToken", "refresh-token"
          json.field "clientId", "client-id"
          json.field "clientSecret", "client-secret"
          json.field "region", "us-east-1"
        end
      end)

      config = CredentialSpecHelper.config({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      config.transport = transport
      credentials = KrikriAwsSsm::CredentialChain.new(config).resolve("sso")
      assert_equal "SSOKEY", credentials.access_key

      refresh = oidc_request
      refute_nil refresh
      body = JSON.parse(refresh.as(HTTP::Request).body || "")
      assert_equal "refresh_token", body["grantType"].as_s
      assert_equal "refresh-token", body["refreshToken"].as_s

      portal = portal_request
      refute_nil portal
      assert_equal "fresh-token", portal.as(HTTP::Request).headers["x-amz-sso_bearer_token"]
    end
  end

  it "rejects a key that differs between the profile and its sso-session" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [sso-session my-sso]
        sso_start_url = https://example.awsapps.com/start
        sso_region = us-east-1

        [profile sso]
        sso_session = my-sso
        sso_start_url = https://other.awsapps.com/start
        sso_account_id = 123456789012
        sso_role_name = MyRole
        INI
      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("sso") }
      assert_includes error.message.to_s, "inconsistent between profile"
      assert_includes error.message.to_s, "sso_start_url"
    end
  end

  it "names the missing required keys of a half-configured SSO profile" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile sso]
        sso_start_url = https://example.awsapps.com/start
        sso_region = us-east-1
        sso_role_name = MyRole
        INI
      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("sso") }
      assert_includes error.message.to_s, "missing required configuration"
      assert_includes error.message.to_s, "sso_account_id"
    end
  end

  it "reports the login error when the token refresh is refused" do
    transport = ->(_request : HTTP::Request, endpoint : URI) do
      if endpoint.host.try(&.starts_with?("oidc."))
        HTTP::Client::Response.new(400, %({"error":"invalid_grant"}))
      else
        HTTP::Client::Response.new(200, CredentialSpecHelper.sso_response)
      end
    end
    CredentialSpecHelper.with_temp_dir do |dir|
      start_url = "https://example.awsapps.com/start"
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile sso]
        sso_start_url = #{start_url}
        sso_region = us-east-1
        sso_account_id = 123456789012
        sso_role_name = MyRole
        INI
      path = File.join(dir, "sso-cache", "#{Digest::SHA1.hexdigest(start_url)}.json")
      CredentialSpecHelper.write(path, JSON.build do |json|
        json.object do
          json.field "accessToken", "expired-token"
          json.field "expiresAt", (Time.utc - 1.minute).to_s("%Y-%m-%dT%H:%M:%SZ")
          json.field "refreshToken", "refresh-token"
          json.field "clientId", "client-id"
          json.field "clientSecret", "client-secret"
        end
      end)

      config = CredentialSpecHelper.config({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      config.transport = transport
      error = assert_raises(KrikriAwsSsm::CredentialsError) do
        KrikriAwsSsm::CredentialChain.new(config).resolve("sso")
      end
      assert_includes error.message.to_s, "Please run aws sso login"
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
