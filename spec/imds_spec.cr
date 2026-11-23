require "./spec_helper"
require "./support/credentials_helper"

include CredentialSpecHelper

private def imds_server(role : String = "test-role",
                        credentials : String = CredentialSpecHelper.metadata_response) : TestHttpServer
  TestHttpServer.new do |request|
    case {request.method, request.resource}
    when {"PUT", "/latest/api/token"}
      TestHttpResponse.new(200, "IMDS-TOKEN")
    when {"GET", "/latest/meta-data/iam/security-credentials/"}
      TestHttpResponse.new(200, "#{role}\n")
    when {"GET", "/latest/meta-data/iam/security-credentials/#{role}"}
      TestHttpResponse.new(200, credentials)
    else
      TestHttpResponse.new(404, "")
    end
  end
end

describe KrikriAwsSsm::CredentialChain::Imds do
  it "performs the IMDSv2 token, role-list and role-document exchange" do
    server = imds_server
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        chain = CredentialSpecHelper.chain(
          {} of String => String, dir, imds_endpoint: server.url)
        credentials = chain.resolve

        assert_equal "METAKEY", credentials.access_key
        assert_equal "METASECRET", credentials.secret_key
        assert_equal "METATOKEN", credentials.session_token
        assert credentials.expires_at

        token_request = server.next_request
        assert_equal "PUT", token_request.method
        assert_equal "/latest/api/token", token_request.resource
        assert_equal "21600", token_request.headers["X-aws-ec2-metadata-token-ttl-seconds"]

        roles_request = server.next_request
        assert_equal "GET", roles_request.method
        assert_equal "/latest/meta-data/iam/security-credentials/", roles_request.resource
        assert_equal "IMDS-TOKEN", roles_request.headers["X-aws-ec2-metadata-token"]

        role_request = server.next_request
        assert_equal "/latest/meta-data/iam/security-credentials/test-role", role_request.resource
        assert_equal "IMDS-TOKEN", role_request.headers["X-aws-ec2-metadata-token"]
      end
    ensure
      server.close
    end
  end

  it "skips IMDS when AWS_EC2_METADATA_DISABLED=true" do
    CredentialSpecHelper.with_temp_dir do |dir|
      env = {"AWS_EC2_METADATA_DISABLED" => "true"}
      # Port 1 would refuse the connection; the disabled flag means we never try.
      chain = CredentialSpecHelper.chain(env, dir, imds_endpoint: "http://127.0.0.1:1")
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
      assert_equal "Unable to locate credentials", error.message
    end
  end

  it "returns nil from IMDS when no role is attached" do
    server = TestHttpServer.new do |request|
      if request.method == "PUT"
        TestHttpResponse.new(200, "IMDS-TOKEN")
      else
        TestHttpResponse.new(200, "")
      end
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "false"}, dir, imds_endpoint: server.url)
        error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
        assert_equal "Unable to locate credentials", error.message
      end
    ensure
      server.close
    end
  end

  it "ignores a non-object role credentials document" do
    server = imds_server(credentials: %(["nope"]))
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "false"}, dir, imds_endpoint: server.url)
        error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
        assert_equal "Unable to locate credentials", error.message
      end
    ensure
      server.close
    end
  end
  it "falls back to token-less IMDSv1 GETs when the token PUT is refused" do
    server = TestHttpServer.new do |request|
      if request.method == "PUT"
        TestHttpResponse.new(403, "")
      elsif request.resource == "/latest/meta-data/iam/security-credentials/"
        TestHttpResponse.new(200, "test-role\n")
      else
        TestHttpResponse.new(200, CredentialSpecHelper.metadata_response)
      end
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "false"}, dir, imds_endpoint: server.url)
        credentials = chain.resolve
        assert_equal "METAKEY", credentials.access_key

        assert_equal "PUT", server.next_request.method
        list_request = server.next_request
        assert_equal "/latest/meta-data/iam/security-credentials/", list_request.resource
        assert_nil list_request.headers["X-aws-ec2-metadata-token"]?
      end
    ensure
      server.close
    end
  end

  it "refuses the v1 fallback when AWS_EC2_METADATA_V1_DISABLED is set" do
    requests = 0
    server = TestHttpServer.new do |_request|
      requests += 1
      TestHttpResponse.new(403, "")
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        env = {
          "AWS_EC2_METADATA_DISABLED"    => "false",
          "AWS_EC2_METADATA_V1_DISABLED" => "true",
        }
        chain = CredentialSpecHelper.chain(env, dir, imds_endpoint: server.url)
        error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
        assert_equal "Unable to locate credentials", error.message
        assert_equal 1, requests
      end
    ensure
      server.close
    end
  end
end

describe KrikriAwsSsm::CredentialChain::Config do
  it "honors the IMDS endpoint, mode, attempts and v1 knobs" do
    explicit = KrikriAwsSsm::CredentialChain::Config.new(env: {
      "AWS_EC2_METADATA_SERVICE_ENDPOINT"      => "http://127.0.0.1:1338",
      "AWS_METADATA_SERVICE_NUM_ATTEMPTS"      => "5",
      "AWS_EC2_METADATA_V1_DISABLED"           => "TRUE",
      "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE" => "IPv6",
    })
    assert_equal "http://127.0.0.1:1338", explicit.imds_endpoint
    assert_equal 5, explicit.imds_attempts
    assert explicit.imds_v1_disabled?

    ipv6 = KrikriAwsSsm::CredentialChain::Config.new(
      env: {"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE" => "IPv6"})
    assert_equal "http://[fd00:ec2::254]", ipv6.imds_endpoint

    default = KrikriAwsSsm::CredentialChain::Config.new(env: {} of String => String)
    assert_equal KrikriAwsSsm::CredentialChain::Config::DEFAULT_IMDS_ENDPOINT,
      default.imds_endpoint
    assert_equal 3, default.imds_attempts
    refute default.imds_v1_disabled?
    assert_equal 2.seconds, default.container_timeout
    assert_equal 3, default.container_attempts
  end
end

describe KrikriAwsSsm::CredentialChain::Ecs do
  it "reads credentials from AWS_CONTAINER_CREDENTIALS_RELATIVE_URI with an auth token" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.metadata_response)
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        env = {
          "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" => "/v2/credentials/relative",
          "AWS_CONTAINER_AUTHORIZATION_TOKEN"      => "container-token",
        }
        chain = CredentialSpecHelper.chain(env, dir, container_endpoint: server.url)
        credentials = chain.resolve

        assert_equal "METAKEY", credentials.access_key
        request = server.next_request
        assert_equal "GET", request.method
        assert_equal "/v2/credentials/relative", request.resource
        assert_equal "container-token", request.headers["Authorization"]
      end
    ensure
      server.close
    end
  end

  it "ignores a non-object container credentials document" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, %(["nope"]))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        env = {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" => "/v2/credentials/relative"}
        chain = CredentialSpecHelper.chain(env, dir, container_endpoint: server.url)
        error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
        assert_equal "ECS container credentials are configured but could not be retrieved",
          error.message
      end
    ensure
      server.close
    end
  end

  it "accepts a loopback full URI and reads the auth token from a file" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.metadata_response)
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        token_file = CredentialSpecHelper.write(File.join(dir, "token"), "file-token\n")
        env = {
          "AWS_CONTAINER_CREDENTIALS_FULL_URI"     => "#{server.url}/full/credentials",
          "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" => token_file,
        }
        chain = CredentialSpecHelper.chain(env, dir)
        credentials = chain.resolve

        assert_equal "METATOKEN", credentials.session_token
        request = server.next_request
        assert_equal "/full/credentials", request.resource
        assert_equal "file-token", request.headers["Authorization"]
      end
    ensure
      server.close
    end
  end

  it "accepts the EKS Pod Identity agent's plain-http default endpoint" do
    captured : HTTP::Request? = nil
    transport = ->(request : HTTP::Request, _endpoint : URI) do
      captured = request
      HTTP::Client::Response.new(200, CredentialSpecHelper.metadata_response)
    end
    config = KrikriAwsSsm::CredentialChain::Config.new(
      env: {"AWS_CONTAINER_CREDENTIALS_FULL_URI" => "http://169.254.170.23/v1/credentials"},
      transport: transport)
    credentials = KrikriAwsSsm::CredentialChain.new(config).resolve

    assert_equal "METAKEY", credentials.access_key
    assert_equal "/v1/credentials", captured.try(&.resource)
  end

  it "sends the endpoint's query string with the request" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.metadata_response)
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        env = {
          "AWS_CONTAINER_CREDENTIALS_FULL_URI" => "#{server.url}/full/credentials?role=web",
        }
        chain = CredentialSpecHelper.chain(env, dir)
        chain.resolve

        assert_equal "/full/credentials?role=web", server.next_request.resource
      end
    ensure
      server.close
    end
  end

  it "prefers the authorization token file over the env var" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.metadata_response)
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        token_file = CredentialSpecHelper.write(File.join(dir, "token"), "file-token\n")
        env = {
          "AWS_CONTAINER_CREDENTIALS_FULL_URI"     => "#{server.url}/full/credentials",
          "AWS_CONTAINER_AUTHORIZATION_TOKEN"      => "env-token",
          "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" => token_file,
        }
        CredentialSpecHelper.chain(env, dir).resolve

        assert_equal "file-token", server.next_request.headers["Authorization"]
      end
    ensure
      server.close
    end
  end

  it "rejects an authorization token containing a line break" do
    CredentialSpecHelper.with_temp_dir do |dir|
      token_file = CredentialSpecHelper.write(File.join(dir, "token"), "tok\nen")
      env = {
        "AWS_CONTAINER_CREDENTIALS_FULL_URI"     => "http://127.0.0.1:1/full/credentials",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" => token_file,
      }
      chain = CredentialSpecHelper.chain(env, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
      assert_includes error.message.to_s, "line break"
    end
  end

  it "retries a failed container request with its own backoff" do
    attempts = 0
    transport = ->(_request : HTTP::Request, _endpoint : URI) do
      attempts += 1
      raise IO::Error.new("connection reset") if attempts < 3
      HTTP::Client::Response.new(200, CredentialSpecHelper.metadata_response)
    end
    CredentialSpecHelper.with_temp_dir do |_dir|
      config = KrikriAwsSsm::CredentialChain::Config.new(
        env: {"AWS_CONTAINER_CREDENTIALS_FULL_URI" => "http://127.0.0.1:1/full/credentials"},
        transport: transport,
        container_retry_delay: 1.millisecond)
      credentials = KrikriAwsSsm::CredentialChain.new(config).resolve
      assert_equal "METAKEY", credentials.access_key
      assert_equal 3, attempts
    end
  end

  it "rejects an insecure non-loopback full URI unless explicitly allowed" do
    CredentialSpecHelper.with_temp_dir do |dir|
      env = {"AWS_CONTAINER_CREDENTIALS_FULL_URI" => "http://10.0.0.1/creds"}
      chain = CredentialSpecHelper.chain(env, dir, allow_insecure: false)
      error = assert_raises(KrikriAwsSsm::ConfigurationError) { chain.resolve }
      assert_includes error.message.to_s, "must use https"
    end
  end
end

describe "container credentials without AWS_EC2_METADATA_DISABLED" do
  it "still uses ECS container credentials when EC2 metadata is disabled" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.metadata_response)
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        env = {
          "AWS_EC2_METADATA_DISABLED"              => "true",
          "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" => "/creds",
        }
        chain = CredentialSpecHelper.chain(env, dir, container_endpoint: server.url)
        credentials = chain.resolve
        assert_equal "METAKEY", credentials.access_key
      end
    ensure
      server.close
    end
  end

  it "fails loudly when a configured container endpoint is broken" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(500, "not here")
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        env = {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" => "/creds"}
        chain = CredentialSpecHelper.chain(env, dir, container_endpoint: server.url)
        error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
        assert_includes error.message.to_s, "configured but could not be retrieved"
      end
    ensure
      server.close
    end
  end
end
