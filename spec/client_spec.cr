require "./spec_helper"

module ClientSpecData
  CREDS          = KrikriAwsSsm::Credentials.new("AKIDEXAMPLE", "secretEXAMPLEKEY", "session-token")
  START_RESPONSE = %({"SessionId":"s-1","StreamUrl":"wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/s-1","TokenValue":"secret-token"})
end

describe KrikriAwsSsm::Client do
  it "signs StartSession and parses SessionId, StreamUrl and TokenValue" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, ClientSpecData::START_RESPONSE)
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      info = KrikriAwsSsm::Client.new(settings).start_session

      assert_equal "s-1", info.session_id
      assert_equal "secret-token", info.token_value
      assert_equal "SessionInfo(s-1)", info.to_s

      request = server.next_request
      assert_equal "POST", request.method
      assert_equal "AmazonSSM.StartSession", request.headers["X-Amz-Target"]
      assert_equal "application/x-amz-json-1.1", request.headers["Content-Type"]
      assert_equal "127.0.0.1:#{server.port}", request.headers["Host"]
      assert_equal %({"Target":"i-0123456789"}), request.body.to_s

      signed = KrikriAwsSsm::Testing::SigV4.verify(
        request, ClientSpecData::CREDS, "us-east-1", "ssm")
      assert_includes signed.signed_headers, "host"
      assert_includes signed.signed_headers, "x-amz-date"
      assert_includes signed.signed_headers, "x-amz-content-sha256"
      assert_includes signed.signed_headers, "x-amz-security-token"
    ensure
      server.close
    end
  end

  it "redacts the token and stream URL from inspect" do
    info = KrikriAwsSsm::SessionInfo.new("s-1",
      "wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/s-1?X-Amz-Signature=deadbeef",
      "secret-token")
    text = info.inspect
    refute_includes text, "secret-token"
    refute_includes text, "X-Amz-Signature"
    assert_includes text, "s-1"
  end

  it "sends DocumentName and Parameters when set" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, ClientSpecData::START_RESPONSE)
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS,
        document: "SSM-SessionManagerRunShell",
        parameters: {"AWS-StartInteractiveCommand" => ["bash -l"]})
      KrikriAwsSsm::Client.new(settings).start_session

      body = JSON.parse(server.next_request.body.to_s)
      assert_equal "SSM-SessionManagerRunShell", body["DocumentName"]
      assert_equal ["bash -l"], body["Parameters"]["AWS-StartInteractiveCommand"].as_a.map(&.as_s)
    ensure
      server.close
    end
  end

  it "sends ResumeSession with the SessionId and parses the new URL and token" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, %({"SessionId":"s-1","StreamUrl":"wss://gateway/s-1",) +
                                %("TokenValue":"new-token"}))
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      info = KrikriAwsSsm::Client.new(settings).resume_session("s-1")

      assert_equal "new-token", info.token_value
      request = server.next_request
      assert_equal "AmazonSSM.ResumeSession", request.headers["X-Amz-Target"]
      assert_equal %({"SessionId":"s-1"}), request.body.to_s
    ensure
      server.close
    end
  end

  it "treats TerminateSession on an already-ended session as success" do
    responses = [
      TestHttpResponse.new(200, ""),
      TestHttpResponse.new(400,
        %({"__type":"com.amazonaws.ssm#SessionNotFound","message":"session not found"})),
    ]
    server = TestHttpServer.new { |_request| responses.shift }
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      client = KrikriAwsSsm::Client.new(settings)
      client.terminate_session("s-1")
      assert_equal "AmazonSSM.TerminateSession", server.next_request.headers["X-Amz-Target"]
      client.terminate_session("s-1")
      assert_equal "AmazonSSM.TerminateSession", server.next_request.headers["X-Amz-Target"]
    ensure
      server.close
    end
  end

  it "maps TargetNotConnected to a typed error with the service text" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(400,
        %({"__type":"com.amazonaws.ssm#TargetNotConnected",) +
        %("message":"i-0123456789 is not connected."}))
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      error = assert_raises(KrikriAwsSsm::TargetNotConnected) do
        KrikriAwsSsm::Client.new(settings).start_session
      end
      assert_equal "TargetNotConnected: i-0123456789 is not connected.", error.message
      assert_equal 400, error.status
    ensure
      server.close
    end
  end

  it "maps AccessDeniedException to AccessDenied" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(400,
        %({"__type":"com.amazonaws.ssm#AccessDeniedException","message":"no ssm:StartSession"}))
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      error = assert_raises(KrikriAwsSsm::AccessDenied) do
        KrikriAwsSsm::Client.new(settings).start_session
      end
      assert_equal "AccessDeniedException: no ssm:StartSession", error.message
    ensure
      server.close
    end
  end

  it "keeps a non-object error body a typed ApiError" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(400, %(["not", "an", "object"]))
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      error = assert_raises(KrikriAwsSsm::ApiError) do
        KrikriAwsSsm::Client.new(settings).start_session
      end
      assert_equal "UnknownError", error.code
      assert_equal 400, error.status
      assert_includes error.message.to_s, "not"
    ensure
      server.close
    end
  end

  it "rejects a non-object success body as a ProtocolError" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, "[]")
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      error = assert_raises(KrikriAwsSsm::ProtocolError) do
        KrikriAwsSsm::Client.new(settings).start_session
      end
      assert_equal "StartSession response was not a JSON object", error.message
    ensure
      server.close
    end
  end

  it "returns no sessions from a non-object DescribeSessions body" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, "42")
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      assert_empty KrikriAwsSsm::Client.new(settings).describe_sessions
    ensure
      server.close
    end
  end

  it "rejects a response missing SessionId, StreamUrl or TokenValue" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, %({"SessionId":"s-1"}))
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      error = assert_raises(KrikriAwsSsm::ProtocolError) do
        KrikriAwsSsm::Client.new(settings).start_session
      end
      assert_equal "StartSession response is missing SessionId, StreamUrl or TokenValue", error.message
    ensure
      server.close
    end
  end

  it "lists sessions with DescribeSessions" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, %({"Sessions":[{"SessionId":"s-1","Status":"Connected"}]}))
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      sessions = KrikriAwsSsm::Client.new(settings).describe_sessions
      assert_equal 1, sessions.size
      assert_equal "s-1", sessions.first["SessionId"].as_s
      assert_equal %({"State":"Active"}), server.next_request.body.to_s
    ensure
      server.close
    end
  end

  it "refuses a plain-http endpoint unless allow_insecure_endpoint is set" do
    settings = KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: "http://127.0.0.1:1234", credentials: ClientSpecData::CREDS)
    error = assert_raises(KrikriAwsSsm::ConfigurationError) do
      KrikriAwsSsm::Client.new(settings).start_session
    end
    assert_match(/must use https/, error.message.to_s)
  end

  it "retries only connection-establishment failures" do
    attempts = 0
    transport = ->(_request : HTTP::Request, _uri : URI) do
      attempts += 1
      raise Socket::ConnectError.new("connection refused") if attempts < 3
      HTTP::Client::Response.new(200, ClientSpecData::START_RESPONSE)
    end
    settings = KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: "http://127.0.0.1:1", allow_insecure_endpoint: true,
      credentials: ClientSpecData::CREDS, retries: 2)
    json = KrikriAwsSsm::AwsJson.new("ssm", "us-east-1", ClientSpecData::CREDS,
      endpoint_url: "http://127.0.0.1:1", allow_insecure_endpoint: true,
      retries: 2, transport: transport)
    info = KrikriAwsSsm::Client.new(settings, aws_json: json).start_session

    assert_equal 3, attempts
    assert_equal "s-1", info.session_id
  end

  it "signs a later control-plane call with refreshed credentials" do
    calls = 0
    chain = KrikriAwsSsm::CredentialChain.new([
      ->(_profile : String?) do
        calls += 1
        KrikriAwsSsm::Credentials.new("KEY#{calls}", "SECRET#{calls}",
          expires_at: Time.utc + 1.minute).as(KrikriAwsSsm::Credentials?)
      end,
    ])
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(200, ClientSpecData::START_RESPONSE)
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true)
      client = KrikriAwsSsm::Client.new(settings, chain)
      client.start_session
      client.describe_sessions

      first = server.next_request.headers["Authorization"].split("Credential=")[1].split('/').first
      second = server.next_request.headers["Authorization"].split("Credential=")[1].split('/').first
      refute_equal first, second
    ensure
      server.close
    end
  end

  it "does not retry failures after a request may have been sent" do
    attempts = 0
    transport = ->(_request : HTTP::Request, _uri : URI) do
      attempts += 1
      raise IO::Error.new("connection reset")
    end
    settings = KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: "http://127.0.0.1:1", allow_insecure_endpoint: true,
      credentials: ClientSpecData::CREDS, retries: 3)
    json = KrikriAwsSsm::AwsJson.new("ssm", "us-east-1", ClientSpecData::CREDS,
      endpoint_url: "http://127.0.0.1:1", allow_insecure_endpoint: true,
      retries: 3, transport: transport)
    assert_raises(IO::Error) do
      KrikriAwsSsm::Client.new(settings, aws_json: json).start_session
    end
    assert_equal 1, attempts
  end

  it "retries a throttled call and keeps the result" do
    attempts = 0
    transport = ->(_request : HTTP::Request, _uri : URI) do
      attempts += 1
      if attempts == 1
        HTTP::Client::Response.new(400,
          %({"__type":"ThrottlingException","message":"slow down"}))
      else
        HTTP::Client::Response.new(200, ClientSpecData::START_RESPONSE)
      end
    end
    settings = KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: "http://127.0.0.1:1", allow_insecure_endpoint: true,
      credentials: ClientSpecData::CREDS, retries: 2)
    json = KrikriAwsSsm::AwsJson.new("ssm", "us-east-1", ClientSpecData::CREDS,
      endpoint_url: "http://127.0.0.1:1", allow_insecure_endpoint: true,
      retries: 2, transport: transport)
    info = KrikriAwsSsm::Client.new(settings, aws_json: json).start_session

    assert_equal 2, attempts
    assert_equal "s-1", info.session_id
  end

  it "wraps a malformed endpoint URL as a ConfigurationError" do
    settings = KrikriAwsSsm::Settings.new("i-0123456789",
      endpoint_url: "http://foo:bar", credentials: ClientSpecData::CREDS)
    error = assert_raises(KrikriAwsSsm::ConfigurationError) do
      KrikriAwsSsm::Client.new(settings).start_session
    end
    assert_includes error.message.to_s, "not a valid URL"
  end

  it "targets the amazonaws.com.cn partition for cn- regions" do
    captured : URI? = nil
    transport = ->(_request : HTTP::Request, uri : URI) do
      captured = uri
      HTTP::Client::Response.new(200, %({"Sessions":[]}))
    end
    json = KrikriAwsSsm::AwsJson.new("ssm", "cn-north-1", ClientSpecData::CREDS,
      transport: transport)
    json.call("DescribeSessions", %({"State":"Active"}))

    assert_equal "ssm.cn-north-1.amazonaws.com.cn", captured.try(&.host)
  end

  it "normalizes the x-amzn-errortype reason suffix" do
    server = TestHttpServer.new do |_request|
      TestHttpResponse.new(400, "denied",
        HTTP::Headers{"x-amzn-errortype" => "AccessDeniedException:http://internal.amazon.com/coral"})
    end
    begin
      settings = KrikriAwsSsm::Settings.new("i-0123456789",
        endpoint_url: server.url, allow_insecure_endpoint: true,
        credentials: ClientSpecData::CREDS)
      error = assert_raises(KrikriAwsSsm::AccessDenied) do
        KrikriAwsSsm::Client.new(settings).start_session
      end
      assert_equal "AccessDeniedException", error.code
      assert_equal 400, error.status
    ensure
      server.close
    end
  end
end

describe KrikriAwsSsm::CredentialChain do
  it "returns the first provider's credentials" do
    creds = KrikriAwsSsm::Credentials.new("AKID", "SECRET")
    chain = KrikriAwsSsm::CredentialChain.new([->(_profile : String?) { creds.as(KrikriAwsSsm::Credentials?) }])
    assert_equal creds, chain.resolve
  end

  it "falls back through providers in order" do
    first = KrikriAwsSsm::Credentials.new("FIRST", "SECRET")
    second = KrikriAwsSsm::Credentials.new("SECOND", "SECRET")
    chain = KrikriAwsSsm::CredentialChain.new([
      ->(_profile : String?) { nil.as(KrikriAwsSsm::Credentials?) },
      ->(_profile : String?) { first.as(KrikriAwsSsm::Credentials?) },
    ])
    assert_equal "FIRST", chain.resolve.access_key
    refute_equal second.access_key, chain.resolve.access_key
  end

  it "raises the botocore text when nothing resolves" do
    chain = KrikriAwsSsm::CredentialChain.new([->(_profile : String?) { nil.as(KrikriAwsSsm::Credentials?) }])
    error = assert_raises(KrikriAwsSsm::CredentialsError) { chain.resolve }
    assert_equal "Unable to locate credentials", error.message
  end

  it "resolves credentials once for concurrent callers" do
    calls = 0
    chain = KrikriAwsSsm::CredentialChain.new([
      ->(_profile : String?) do
        calls += 1
        KrikriAwsSsm::Credentials.new("KEY", "SECRET").as(KrikriAwsSsm::Credentials?)
      end,
    ])
    settings = KrikriAwsSsm::Settings.new("i-0123456789")
    client = KrikriAwsSsm::Client.new(settings, chain)

    results = Channel(KrikriAwsSsm::Credentials).new(4)
    4.times { spawn { results.send(client.credentials) } }
    4.times { assert_equal "KEY", receive_with_timeout(results).access_key }
    assert_equal 1, calls
  end

  it "serves a second resolve from the cache without another provider call" do
    calls = 0
    chain = KrikriAwsSsm::CredentialChain.new([
      ->(_profile : String?) do
        calls += 1
        KrikriAwsSsm::Credentials.new("KEY", "SECRET").as(KrikriAwsSsm::Credentials?)
      end,
    ])
    assert_equal "KEY", chain.resolve.access_key
    assert_equal "KEY", chain.resolve.access_key
    assert_equal 1, calls
  end

  it "marks credentials near expiry for refresh" do
    expiring = KrikriAwsSsm::Credentials.new("A", "B", expires_at: Time.utc + 2.minutes)
    assert expiring.refresh_needed?
    refute expiring.expired?
    assert KrikriAwsSsm::Credentials.new("A", "B", expires_at: Time.utc - 1.minute).expired?
  end
end
