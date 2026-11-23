require "./spec_helper"
require "./support/credentials_helper"

include CredentialSpecHelper

# A terminal-shaped IO: reads the fixed buffer and claims to be a tty, so the
# MFA prompt path runs without a real terminal or stty.
private class FakeTty < IO::Memory
  def tty? : Bool
    true
  end
end

# A tty that never produces a line, to exercise the MFA prompt deadline.
private class BlockingTty < IO
  def tty? : Bool
    true
  end

  def read(slice : Bytes) : Int32
    sleep
    0
  end

  def write(slice : Bytes) : Nil
  end
end

describe KrikriAwsSsm::CredentialChain do
  it "never reveals secrets from Credentials#to_s" do
    credentials = KrikriAwsSsm::Credentials.new("AKIDEXAMPLE", "super-secret", "session-token")
    text = credentials.to_s
    assert_includes text, "AKID..."
    refute_includes text, "super-secret"
    refute_includes text, "session-token"
  end

  it "never reveals secrets from Credentials#inspect" do
    credentials = KrikriAwsSsm::Credentials.new("AKIDEXAMPLE", "super-secret", "session-token")
    text = credentials.inspect
    refute_includes text, "super-secret"
    refute_includes text, "session-token"
    assert_includes text, "AKID..."
  end

  it "prefers environment credentials over any profile" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "credentials"),
        "[default]\naws_access_key_id = PROFILEKEY\naws_secret_access_key = PROFILESECRET\n")
      env = {
        "AWS_ACCESS_KEY_ID"         => "ENVKEY",
        "AWS_SECRET_ACCESS_KEY"     => "ENVSECRET",
        "AWS_SESSION_TOKEN"         => "ENVTOKEN",
        "AWS_EC2_METADATA_DISABLED" => "true",
      }
      credentials = CredentialSpecHelper.chain(env, dir).resolve
      assert_equal "ENVKEY", credentials.access_key
      assert_equal "ENVSECRET", credentials.secret_key
      assert_equal "ENVTOKEN", credentials.session_token
    end
  end

  it "accepts the legacy environment key names" do
    CredentialSpecHelper.with_temp_dir do |dir|
      env = {
        "AWS_ACCESS_KEY"            => "LEGACYKEY",
        "AWS_SECRET_KEY"            => "LEGACYSECRET",
        "AWS_SESSION_TOKEN"         => "LEGACYTOKEN",
        "AWS_EC2_METADATA_DISABLED" => "true",
      }
      credentials = CredentialSpecHelper.chain(env, dir).resolve
      assert_equal "LEGACYKEY", credentials.access_key
      assert_equal "LEGACYSECRET", credentials.secret_key
      assert_equal "LEGACYTOKEN", credentials.session_token
    end
  end

  it "treats empty environment credentials as unset, like botocore" do
    CredentialSpecHelper.with_temp_dir do |dir|
      env = {
        "AWS_ACCESS_KEY_ID"         => "",
        "AWS_SECRET_ACCESS_KEY"     => "",
        "AWS_ACCESS_KEY"            => "LEGACYKEY",
        "AWS_SECRET_KEY"            => "LEGACYSECRET",
        "AWS_EC2_METADATA_DISABLED" => "true",
      }
      credentials = CredentialSpecHelper.chain(env, dir).resolve
      assert_equal "LEGACYKEY", credentials.access_key
      assert_equal "LEGACYSECRET", credentials.secret_key
    end
  end

  it "names the missing key of a partial static profile" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "credentials"),
        "[partial]\naws_access_key_id = PARTIALKEY\n")
      env = {"AWS_EC2_METADATA_DISABLED" => "true"}
      chain = CredentialSpecHelper.chain(env, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("partial") }
      assert_includes error.message.to_s, "Partial credentials"
      assert_includes error.message.to_s, "aws_secret_access_key"
    end
  end

  it "selects AWS_PROFILE and merges config and credentials with credentials winning" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "credentials"),
        "[work]\naws_access_key_id = CREDSKEY\naws_secret_access_key = CREDSSECRET\n")
      CredentialSpecHelper.write(File.join(dir, "config"),
        "[profile work]\naws_secret_access_key = CONFIGSECRET\nregion = us-west-2\n")
      env = {"AWS_PROFILE" => "work", "AWS_EC2_METADATA_DISABLED" => "true"}
      credentials = CredentialSpecHelper.chain(env, dir).resolve
      assert_equal "CREDSKEY", credentials.access_key
      assert_equal "CREDSSECRET", credentials.secret_key
    end
  end

  it "lets an explicit profile argument override AWS_PROFILE" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile from-env]
        aws_access_key_id = ENVPROFILE
        aws_secret_access_key = ENVSECRET

        [profile explicit]
        aws_access_key_id = EXPLICITKEY
        aws_secret_access_key = EXPLICITSECRET
        INI
      env = {"AWS_PROFILE" => "from-env", "AWS_EC2_METADATA_DISABLED" => "true"}
      credentials = CredentialSpecHelper.chain(env, dir).resolve("explicit")
      assert_equal "EXPLICITKEY", credentials.access_key
    end
  end

  it "uses AWS_DEFAULT_PROFILE as a fallback profile selector" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"),
        "[profile legacy-default]\naws_access_key_id = DEFAULTENVKEY\n" \
        "aws_secret_access_key = DEFAULTENVSECRET\n")
      env = {"AWS_DEFAULT_PROFILE" => "legacy-default", "AWS_EC2_METADATA_DISABLED" => "true"}
      credentials = CredentialSpecHelper.chain(env, dir).resolve
      assert_equal "DEFAULTENVKEY", credentials.access_key
    end
  end

  it "uses the default profile when nothing selects another one" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"),
        "[default]\naws_access_key_id = DEFAULTKEY\naws_secret_access_key = DEFAULTSECRET\n")
      credentials = CredentialSpecHelper.chain(
        {"AWS_EC2_METADATA_DISABLED" => "true"}, dir).resolve
      assert_equal "DEFAULTKEY", credentials.access_key
    end
  end

  it "honors AWS_SHARED_CREDENTIALS_FILE and AWS_CONFIG_FILE" do
    CredentialSpecHelper.with_temp_dir do |dir|
      credentials_file = CredentialSpecHelper.write(File.join(dir, "custom-creds"),
        "[p]\naws_access_key_id = CUSTOMKEY\naws_secret_access_key = CUSTOMSECRET\n")
      config_file = CredentialSpecHelper.write(File.join(dir, "custom-config"),
        "[profile p]\nregion = us-east-1\n")
      env = {
        "AWS_SHARED_CREDENTIALS_FILE" => credentials_file,
        "AWS_CONFIG_FILE"             => config_file,
        "AWS_PROFILE"                 => "p",
        "AWS_EC2_METADATA_DISABLED"   => "true",
      }
      config = KrikriAwsSsm::CredentialChain::Config.new(env: env, home_dir: dir)
      credentials = KrikriAwsSsm::CredentialChain.new(config).resolve
      assert_equal "CUSTOMKEY", credentials.access_key
    end
  end

  it "runs credential_process and parses its JSON" do
    CredentialSpecHelper.with_temp_dir do |dir|
      command = %(printf '%s' '{"Version":1,"AccessKeyId":"PROCESSKEY",) +
                %("SecretAccessKey":"PROCESSSECRET","SessionToken":"PROCESSTOKEN",) +
                %("Expiration":"#{(Time.utc + 1.hour).to_s("%Y-%m-%dT%H:%M:%SZ")}"}')
      CredentialSpecHelper.write(File.join(dir, "config"),
        "[profile proc]\ncredential_process = #{command}\n")
      credentials = CredentialSpecHelper.chain(
        {"AWS_EC2_METADATA_DISABLED" => "true"}, dir).resolve("proc")
      assert_equal "PROCESSKEY", credentials.access_key
      assert_equal "PROCESSSECRET", credentials.secret_key
      assert_equal "PROCESSTOKEN", credentials.session_token
      refute credentials.expired?
    end
  end

  it "rejects a non-object credential_process output with a CredentialsError" do
    CredentialSpecHelper.with_temp_dir do |dir|
      command = %(printf '%s' '["nope"]')
      CredentialSpecHelper.write(File.join(dir, "config"),
        "[profile proc]\ncredential_process = #{command}\n")
      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("proc") }
      assert_includes error.message.to_s, "non-object"
    end
  end

  it "re-runs credential_process from refresh when the credentials are near expiry" do
    CredentialSpecHelper.with_temp_dir do |dir|
      script = File.join(dir, "process.sh")
      counter = File.join(dir, "count")
      expiration = (Time.utc + 2.minutes).to_s("%Y-%m-%dT%H:%M:%SZ")
      CredentialSpecHelper.write(script, <<-SH)
        #!/bin/sh
        count=0
        if [ -f "#{counter}" ]; then count=$(cat "#{counter}"); fi
        count=$((count + 1))
        echo "$count" > "#{counter}"
        printf '{"Version":1,"AccessKeyId":"PROCESS%s","SecretAccessKey":"SECRET%s","Expiration":"#{expiration}"}' "$count" "$count"
        SH
      File.chmod(script, 0o755)
      CredentialSpecHelper.write(File.join(dir, "config"),
        "[profile proc]\ncredential_process = #{script}\n")

      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      first = chain.resolve("proc")
      assert_equal "PROCESS1", first.access_key
      assert first.refresh_needed?

      second = chain.refresh(first)
      assert_equal "PROCESS2", second.access_key
      assert_equal "2", File.read(counter).strip
    end
  end

  it "returns credentials the chain never issued unchanged from refresh" do
    calls = 0
    chain = KrikriAwsSsm::CredentialChain.new([
      ->(_profile : String?) do
        calls += 1
        KrikriAwsSsm::Credentials.new("KEY", "SECRET",
          expires_at: Time.utc + 1.minute).as(KrikriAwsSsm::Credentials?)
      end,
    ])
    foreign = KrikriAwsSsm::Credentials.new("FOREIGN", "FOREIGNSECRET",
      expires_at: Time.utc + 1.minute)

    assert_equal foreign, chain.refresh(foreign)
    assert_equal 0, calls
  end

  it "resolves one refresh for concurrent callers holding the same expiring credentials" do
    calls = 0
    chain = KrikriAwsSsm::CredentialChain.new([
      ->(_profile : String?) do
        calls += 1
        expires_at = calls == 1 ? Time.utc + 1.minute : nil
        KrikriAwsSsm::Credentials.new("KEY#{calls}", "SECRET#{calls}",
          expires_at: expires_at).as(KrikriAwsSsm::Credentials?)
      end,
    ])
    first = chain.resolve
    refreshed = chain.refresh(first)
    assert_equal 2, calls

    results = Channel(KrikriAwsSsm::Credentials).new(5)
    5.times { spawn { results.send(chain.refresh(first)) } }
    5.times { assert_equal refreshed, receive_with_timeout(results) }
    assert_equal 2, calls
  end

  it "raises a secret-free CredentialsError when credential_process fails" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"),
        "[profile broken]\ncredential_process = printf 'boom' >&2; exit 3\n")
      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("broken") }
      assert_includes error.message.to_s, "status 3"
      assert_includes error.message.to_s, "boom"
      refute_includes error.message.to_s, "SecretAccessKey"
    end
  end

  it "assumes a role from source_profile and signs the STS query with the source key" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET
          aws_session_token = BASETOKEN

          [profile role]
          role_arn = arn:aws:iam::123456789012:role/TestRole
          source_profile = base
          role_session_name = custom-session
          external_id = external-123
          duration_seconds = 900
          region = us-east-1
          INI

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url)
        credentials = chain.resolve("role")

        assert_equal "ASSUMEDKEY", credentials.access_key
        assert_equal "ASSUMEDSECRET", credentials.secret_key
        assert_equal "ASSUMEDTOKEN", credentials.session_token
        assert credentials.expires_at

        request = server.next_request
        assert_equal "POST", request.method
        assert_equal "application/x-www-form-urlencoded; charset=utf-8",
          request.headers["Content-Type"]
        params = CredentialSpecHelper.form_params(request.body.to_s)
        assert_equal "AssumeRole", params["Action"]
        assert_equal "2011-06-15", params["Version"]
        assert_equal "arn:aws:iam::123456789012:role/TestRole", params["RoleArn"]
        assert_equal "custom-session", params["RoleSessionName"]
        assert_equal "external-123", params["ExternalId"]
        assert_equal "900", params["DurationSeconds"]
        authorization = request.headers["Authorization"]? ||
                        raise "missing Authorization header"
        assert authorization.starts_with?("AWS4-HMAC-SHA256 Credential=BASEKEY/")
        assert_equal "BASETOKEN", request.headers["X-Amz-Security-Token"]
      end
    ensure
      server.close
    end
  end

  it "resolves STS through an injected transport seam" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile base]
        aws_access_key_id = BASEKEY
        aws_secret_access_key = BASESECRET

        [profile role]
        role_arn = arn:aws:iam::123456789012:role/SeamRole
        source_profile = base
        region = us-east-1
        INI

      seen = [] of HTTP::Request
      transport = ->(request : HTTP::Request, _uri : URI) do
        seen << request
        HTTP::Client::Response.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
      end
      config = KrikriAwsSsm::CredentialChain::Config.new(
        env: {"AWS_EC2_METADATA_DISABLED" => "true"},
        shared_credentials_file: File.join(dir, "credentials"),
        shared_config_file: File.join(dir, "config"),
        sts_endpoint_url: "http://sts.test",
        allow_insecure_endpoint: true,
        transport: transport)
      credentials = KrikriAwsSsm::CredentialChain.new(config).resolve("role")

      assert_equal "ASSUMEDKEY", credentials.access_key
      assert_equal 1, seen.size
      params = CredentialSpecHelper.form_params(seen.first.body.to_s)
      assert_equal "AssumeRole", params["Action"]
    end
  end

  it "recursively assumes chained source_profile roles" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile middle]
          role_arn = arn:aws:iam::123456789012:role/Middle
          source_profile = base
          region = us-east-1

          [profile top]
          role_arn = arn:aws:iam::123456789012:role/Top
          source_profile = middle
          region = us-east-1
          INI

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url)
        credentials = chain.resolve("top")
        assert_equal "ASSUMEDKEY", credentials.access_key

        first = server.next_request
        first_authorization = first.headers["Authorization"]? ||
                              raise "missing Authorization header"
        assert first_authorization.starts_with?("AWS4-HMAC-SHA256 Credential=BASEKEY/")

        second = server.next_request
        second_authorization = second.headers["Authorization"]? ||
                               raise "missing Authorization header"
        assert second_authorization.starts_with?("AWS4-HMAC-SHA256 Credential=ASSUMEDKEY/")
        assert_equal "ASSUMEDTOKEN", second.headers["X-Amz-Security-Token"]
      end
    ensure
      server.close
    end
  end

  it "detects source_profile cycles" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile a]
        role_arn = arn:aws:iam::123456789012:role/A
        source_profile = b

        [profile b]
        role_arn = arn:aws:iam::123456789012:role/B
        source_profile = a
        INI
      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("a") }
      assert_includes error.message.to_s, "Infinite loop"
    end
  end

  it "resolves credential_source Ec2InstanceMetadata before AssumeRole" do
    imds = TestHttpServer.new do |request|
      case {request.method, request.resource}
      when {"PUT", "/latest/api/token"}
        TestHttpResponse.new(200, "IMDS-TOKEN")
      when {"GET", "/latest/meta-data/iam/security-credentials/"}
        TestHttpResponse.new(200, "test-role\n")
      else
        TestHttpResponse.new(200, CredentialSpecHelper.metadata_response)
      end
    end
    sts = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile imds-role]
          role_arn = arn:aws:iam::123456789012:role/ImdsRole
          credential_source = Ec2InstanceMetadata
          region = us-east-1
          INI
        chain = CredentialSpecHelper.chain(
          {} of String => String, dir, sts_endpoint: sts.url, imds_endpoint: imds.url)
        credentials = chain.resolve("imds-role")
        assert_equal "ASSUMEDKEY", credentials.access_key

        token_request = imds.next_request
        assert_equal "PUT", token_request.method
        assert_equal "21600", token_request.headers["X-aws-ec2-metadata-token-ttl-seconds"]
        role_request = imds.next_request
        assert_equal "IMDS-TOKEN", role_request.headers["X-aws-ec2-metadata-token"]
        credentials_request = imds.next_request
        assert_equal "/latest/meta-data/iam/security-credentials/test-role",
          credentials_request.resource

        authorization = sts.next_request.headers["Authorization"]? ||
                        raise "missing Authorization header"
        assert authorization.starts_with?("AWS4-HMAC-SHA256 Credential=METAKEY/")
      end
    ensure
      imds.close
      sts.close
    end
  end

  it "resolves credential_source EcsContainer before AssumeRole" do
    ecs = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.metadata_response)
    end
    sts = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile ecs-role]
          role_arn = arn:aws:iam::123456789012:role/EcsRole
          credential_source = EcsContainer
          region = us-east-1
          INI
        env = {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" => "/v2/credentials/abc"}
        chain = CredentialSpecHelper.chain(
          env, dir, sts_endpoint: sts.url, container_endpoint: ecs.url)
        credentials = chain.resolve("ecs-role")
        assert_equal "ASSUMEDKEY", credentials.access_key

        ecs_request = ecs.next_request
        assert_equal "GET", ecs_request.method
        assert_equal "/v2/credentials/abc", ecs_request.resource
        authorization = sts.next_request.headers["Authorization"]? ||
                        raise "missing Authorization header"
        assert authorization.starts_with?("AWS4-HMAC-SHA256 Credential=METAKEY/")
      end
    ensure
      ecs.close
      sts.close
    end
  end

  it "resolves environment web identity through unsigned AssumeRoleWithWebIdentity" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRoleWithWebIdentity"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        token_file = CredentialSpecHelper.write(File.join(dir, "token"), "web-identity-token\n")
        env = {
          "AWS_ROLE_ARN"                => "arn:aws:iam::123456789012:role/WebIdentity",
          "AWS_WEB_IDENTITY_TOKEN_FILE" => token_file,
          "AWS_ROLE_SESSION_NAME"       => "irsa-session",
          "AWS_EC2_METADATA_DISABLED"   => "true",
        }
        chain = CredentialSpecHelper.chain(env, dir, sts_endpoint: server.url)
        credentials = chain.resolve
        assert_equal "ASSUMEDTOKEN", credentials.session_token

        request = server.next_request
        params = CredentialSpecHelper.form_params(request.body.to_s)
        assert_equal "AssumeRoleWithWebIdentity", params["Action"]
        assert_equal "arn:aws:iam::123456789012:role/WebIdentity", params["RoleArn"]
        assert_equal "irsa-session", params["RoleSessionName"]
        assert_equal "web-identity-token", params["WebIdentityToken"]
        assert_nil request.headers["Authorization"]?
      end
    ensure
      server.close
    end
  end

  it "resolves profile web_identity_token_file through STS" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRoleWithWebIdentity"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        token_file = CredentialSpecHelper.write(File.join(dir, "token"), "profile-token")
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile irsa]
          role_arn = arn:aws:iam::123456789012:role/ProfileWebIdentity
          web_identity_token_file = #{token_file}
          role_session_name = profile-session
          region = us-east-1
          INI
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url)
        credentials = chain.resolve("irsa")
        assert_equal "ASSUMEDKEY", credentials.access_key

        request = server.next_request
        params = CredentialSpecHelper.form_params(request.body.to_s)
        assert_equal "profile-token", params["WebIdentityToken"]
        assert_equal "profile-session", params["RoleSessionName"]
        assert_nil request.headers["Authorization"]?
      end
    ensure
      server.close
    end
  end

  it "asks the injected provider for the MFA code and sends SerialNumber and TokenCode" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile mfa]
          role_arn = arn:aws:iam::123456789012:role/MfaRole
          source_profile = base
          mfa_serial = arn:aws:iam::123456789012:mfa/user
          INI

        seen = [] of String
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url,
          mfa_token_provider: ->(serial : String) { seen << serial; "123456" })
        credentials = chain.resolve("mfa")

        assert_equal "ASSUMEDKEY", credentials.access_key
        assert_equal ["arn:aws:iam::123456789012:mfa/user"], seen
        params = CredentialSpecHelper.form_params(server.next_request.body.to_s)
        assert_equal "arn:aws:iam::123456789012:mfa/user", params["SerialNumber"]
        assert_equal "123456", params["TokenCode"]
      end
    ensure
      server.close
    end
  end

  it "prompts on the terminal for an MFA code when no provider is injected" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile mfa]
          role_arn = arn:aws:iam::123456789012:role/MfaRole
          source_profile = base
          mfa_serial = arn:aws:iam::123456789012:mfa/user
          INI

        output = IO::Memory.new
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url,
          mfa_input: FakeTty.new("123456\n"), mfa_output: output)
        credentials = chain.resolve("mfa")

        assert_equal "ASSUMEDKEY", credentials.access_key
        params = CredentialSpecHelper.form_params(server.next_request.body.to_s)
        assert_equal "123456", params["TokenCode"]
        assert_includes output.to_s,
          "Enter MFA code for arn:aws:iam::123456789012:mfa/user: "
        # An injected IO cannot hide its input, so the prompt says so.
        assert_includes output.to_s, "Warning: MFA code input may be echoed."
      end
    ensure
      server.close
    end
  end

  it "suppresses terminal echo while reading the MFA code" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile mfa]
          role_arn = arn:aws:iam::123456789012:role/MfaRole
          source_profile = base
          mfa_serial = arn:aws:iam::123456789012:mfa/user
          INI

        echo_calls = [] of Bool
        output = IO::Memory.new
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url,
          mfa_input: FakeTty.new("123456\n"), mfa_output: output,
          mfa_echo_control: ->(enabled : Bool) { echo_calls << enabled; true })
        chain.resolve("mfa")

        assert_equal [false, true], echo_calls
        refute_includes output.to_s, "may be echoed"
      end
    ensure
      server.close
    end
  end

  it "raises when the MFA prompt reaches end of input without a code" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile base]
        aws_access_key_id = BASEKEY
        aws_secret_access_key = BASESECRET

        [profile mfa]
        role_arn = arn:aws:iam::123456789012:role/MfaRole
        source_profile = base
        mfa_serial = arn:aws:iam::123456789012:mfa/user
        INI
      chain = CredentialSpecHelper.chain(
        {"AWS_EC2_METADATA_DISABLED" => "true"}, dir,
        mfa_input: FakeTty.new(""), mfa_output: IO::Memory.new)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("mfa") }
      assert_includes error.message.to_s, "No MFA code was entered"
      assert_includes error.message.to_s, "arn:aws:iam::123456789012:mfa/user"
    end
  end

  it "times out a hung MFA prompt instead of holding the chain" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile base]
        aws_access_key_id = BASEKEY
        aws_secret_access_key = BASESECRET

        [profile mfa]
        role_arn = arn:aws:iam::123456789012:role/MfaRole
        source_profile = base
        mfa_serial = arn:aws:iam::123456789012:mfa/user
        INI
      config = CredentialSpecHelper.config(
        {"AWS_EC2_METADATA_DISABLED" => "true"}, dir,
        mfa_input: BlockingTty.new, mfa_output: IO::Memory.new,
        mfa_echo_control: ->(_enabled : Bool) { true })
      config.mfa_timeout = 100.milliseconds
      chain = KrikriAwsSsm::CredentialChain.new(config)

      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("mfa") }
      assert_includes error.message.to_s, "Timed out waiting for the MFA code"
    end
  end

  it "keeps the MFA code out of an STS error message" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(403, <<-XML)
        <ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <Error>
            <Type>Sender</Type>
            <Code>AccessDenied</Code>
            <Message>MultiFactorAuthentication failed</Message>
          </Error>
        </ErrorResponse>
        XML
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile mfa]
          role_arn = arn:aws:iam::123456789012:role/MfaRole
          source_profile = base
          mfa_serial = arn:aws:iam::123456789012:mfa/user
          INI

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url,
          mfa_token_provider: ->(_serial : String) { "654321" })
        error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("mfa") }
        assert_includes error.message.to_s, "STS AssumeRole failed"
        assert_includes error.message.to_s, "MultiFactorAuthentication failed"
        refute_includes error.message.to_s, "654321"
      end
    ensure
      server.close
    end
  end

  it "prompts once per assume-role step with each profile's own mfa_serial" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile mid]
          role_arn = arn:aws:iam::123456789012:role/MidRole
          source_profile = base
          mfa_serial = arn:aws:iam::123456789012:mfa/mid

          [profile top]
          role_arn = arn:aws:iam::123456789012:role/TopRole
          source_profile = mid
          mfa_serial = arn:aws:iam::123456789012:mfa/top
          INI

        seen = [] of String
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url,
          mfa_token_provider: ->(serial : String) { seen << serial; "123456" })
        chain.resolve("top")

        assert_equal ["arn:aws:iam::123456789012:mfa/mid",
                      "arn:aws:iam::123456789012:mfa/top"], seen
        mid_params = CredentialSpecHelper.form_params(server.next_request.body.to_s)
        top_params = CredentialSpecHelper.form_params(server.next_request.body.to_s)
        assert_equal "arn:aws:iam::123456789012:mfa/mid", mid_params["SerialNumber"]
        assert_equal "arn:aws:iam::123456789012:mfa/top", top_params["SerialNumber"]
      end
    ensure
      server.close
    end
  end

  it "refuses an MFA profile when no terminal can prompt and no provider exists" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile base]
        aws_access_key_id = BASEKEY
        aws_secret_access_key = BASESECRET

        [profile mfa]
        role_arn = arn:aws:iam::123456789012:role/MfaRole
        source_profile = base
        mfa_serial = arn:aws:iam::123456789012:mfa/user
        INI
      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("mfa") }
      assert_includes error.message.to_s, "MFA is required"
      assert_includes error.message.to_s, "arn:aws:iam::123456789012:mfa/user"
      assert_includes error.message.to_s, "no terminal"
    end
  end

  it "rejects an empty MFA code from the injected provider" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile base]
        aws_access_key_id = BASEKEY
        aws_secret_access_key = BASESECRET

        [profile mfa]
        role_arn = arn:aws:iam::123456789012:role/MfaRole
        source_profile = base
        mfa_serial = arn:aws:iam::123456789012:mfa/user
        INI
      chain = CredentialSpecHelper.chain(
        {"AWS_EC2_METADATA_DISABLED" => "true"}, dir,
        mfa_token_provider: ->(_serial : String) { "  " })
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve("mfa") }
      assert_includes error.message.to_s, "returned no code"
    end
  end

  it "re-prompts for a fresh MFA code when the assumed role credentials refresh" do
    fetches = 0
    server = TestHttpServer.new do |_request|
      fetches += 1
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole",
        access_key: "ASSUMED#{fetches}", expires_at: Time.utc + 2.minutes))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile mfa]
          role_arn = arn:aws:iam::123456789012:role/MfaRole
          source_profile = base
          mfa_serial = arn:aws:iam::123456789012:mfa/user
          INI

        calls = 0
        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url,
          mfa_token_provider: ->(_serial : String) { calls += 1; calls == 1 ? "111111" : "222222" })
        first = chain.resolve("mfa")
        assert first.refresh_needed?
        second = chain.refresh(first)
        assert_equal "ASSUMED1", first.access_key
        assert_equal "ASSUMED2", second.access_key

        assert_equal 2, calls
        first_params = CredentialSpecHelper.form_params(server.next_request.body.to_s)
        second_params = CredentialSpecHelper.form_params(server.next_request.body.to_s)
        assert_equal "111111", first_params["TokenCode"]
        assert_equal "222222", second_params["TokenCode"]
      end
    ensure
      server.close
    end
  end

  it "keeps Client working with CredentialChain.default" do
    CredentialSpecHelper.with_temp_dir do |dir|
      env = {
        "AWS_ACCESS_KEY_ID"         => "CLIENTKEY",
        "AWS_SECRET_ACCESS_KEY"     => "CLIENTSECRET",
        "AWS_EC2_METADATA_DISABLED" => "true",
      }
      chain = KrikriAwsSsm::CredentialChain.default(CredentialSpecHelper.config(env, dir))
      settings = KrikriAwsSsm::Settings.new("i-0123456789")
      client = KrikriAwsSsm::Client.new(settings, chain)
      assert_equal "CLIENTKEY", client.credentials.access_key
      assert_equal "CLIENTSECRET", client.credentials.secret_key
    end
  end

  it "raises the botocore text when nothing resolves" do
    CredentialSpecHelper.with_temp_dir do |dir|
      chain = CredentialSpecHelper.chain({"AWS_EC2_METADATA_DISABLED" => "true"}, dir)
      error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
      assert_equal "Unable to locate credentials", error.message
    end
  end
end

describe "KrikriAwsSsm::CredentialChain profile precedence" do
  it "assumes the role when a top-level profile also has static keys" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile self-sourcing]
          aws_access_key_id = SELFKEY
          aws_secret_access_key = SELFSECRET
          role_arn = arn:aws:iam::123456789012:role/SelfRole
          source_profile = self-sourcing
          region = us-east-1
          INI

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url)
        credentials = chain.resolve("self-sourcing")

        assert_equal "ASSUMEDKEY", credentials.access_key
        request = server.next_request
        authorization = request.headers["Authorization"]? || raise "missing Authorization"
        assert authorization.starts_with?("AWS4-HMAC-SHA256 Credential=SELFKEY/")
      end
    ensure
      server.close
    end
  end

  it "prefers role_arn over credential_process in the same top-level profile" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile both]
          role_arn = arn:aws:iam::123456789012:role/BothRole
          source_profile = base
          credential_process = /bin/false
          region = us-east-1
          INI

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url)
        credentials = chain.resolve("both")
        assert_equal "ASSUMEDKEY", credentials.access_key
      end
    ensure
      server.close
    end
  end

  it "lets a source profile's static keys win over that profile's own role_arn" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile middle]
          aws_access_key_id = MIDKEY
          aws_secret_access_key = MIDSECRET
          role_arn = arn:aws:iam::123456789012:role/IgnoredRole
          source_profile = base

          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile top]
          role_arn = arn:aws:iam::123456789012:role/TopRole
          source_profile = middle
          region = us-east-1
          INI

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url)
        credentials = chain.resolve("top")

        assert_equal "ASSUMEDKEY", credentials.access_key
        request = server.next_request
        authorization = request.headers["Authorization"]? || raise "missing Authorization"
        assert authorization.starts_with?("AWS4-HMAC-SHA256 Credential=MIDKEY/")
      end
    ensure
      server.close
    end
  end

  it "signs a regional STS endpoint with its region" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, CredentialSpecHelper.sts_response("AssumeRole"))
    end
    begin
      CredentialSpecHelper.with_temp_dir do |dir|
        CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
          [profile base]
          aws_access_key_id = BASEKEY
          aws_secret_access_key = BASESECRET

          [profile role]
          role_arn = arn:aws:iam::123456789012:role/Regional
          source_profile = base
          region = us-west-2
          INI

        chain = CredentialSpecHelper.chain(
          {"AWS_EC2_METADATA_DISABLED" => "true"}, dir, sts_endpoint: server.url)
        chain.resolve("role")

        authorization = server.next_request.headers["Authorization"]?
        assert authorization.try(&.includes?("/us-west-2/sts/aws4_request"))
      end
    ensure
      server.close
    end
  end

  it "wraps an STS transport timeout in CredentialsError" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile base]
        aws_access_key_id = BASEKEY
        aws_secret_access_key = BASESECRET

        [profile role]
        role_arn = arn:aws:iam::123456789012:role/Timeout
        source_profile = base
        region = us-east-1
        INI

      transport = ->(_request : HTTP::Request, _uri : URI) do
        raise IO::TimeoutError.new("read timed out")
      end
      config = KrikriAwsSsm::CredentialChain::Config.new(
        env: {"AWS_EC2_METADATA_DISABLED" => "true"},
        shared_credentials_file: File.join(dir, "credentials"),
        shared_config_file: File.join(dir, "config"),
        sts_endpoint_url: "http://sts.test",
        allow_insecure_endpoint: true,
        transport: transport)
      error = assert_raises(KrikriAwsSsm::CredentialsError) do
        KrikriAwsSsm::CredentialChain.new(config).resolve("role")
      end
      assert_includes error.message.to_s, "STS AssumeRole request failed"
    end
  end

  it "times out a hung credential_process" do
    CredentialSpecHelper.with_temp_dir do |dir|
      CredentialSpecHelper.write(File.join(dir, "config"), <<-INI)
        [profile hung]
        credential_process = sleep 5
        INI

      config = KrikriAwsSsm::CredentialChain::Config.new(
        env: {"AWS_EC2_METADATA_DISABLED" => "true"},
        shared_credentials_file: File.join(dir, "credentials"),
        shared_config_file: File.join(dir, "config"),
        process_timeout: 100.milliseconds)
      error = assert_raises(KrikriAwsSsm::CredentialsError) do
        KrikriAwsSsm::CredentialChain.new(config).resolve("hung")
      end
      assert_includes error.message.to_s, "timed out"
    end
  end
end
