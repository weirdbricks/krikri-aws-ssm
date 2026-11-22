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

  it "rejects an insecure non-loopback full URI unless explicitly allowed" do
    CredentialSpecHelper.with_temp_dir do |dir|
      env = {"AWS_CONTAINER_CREDENTIALS_FULL_URI" => "http://169.254.170.2/creds"}
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
