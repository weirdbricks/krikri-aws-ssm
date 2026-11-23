require "./spec_helper"

describe KrikriAwsSsm::Handshake do
  it "serializes a processed action with a numeric status and null result" do
    action = KrikriAwsSsm::Handshake::ProcessedClientAction.new(
      KrikriAwsSsm::ActionType::SESSION_TYPE, KrikriAwsSsm::ActionStatus::Success.value)
    assert_equal(
      %({"ActionType":"SessionType","ActionStatus":1,"ActionResult":null,"Error":""}),
      action.to_json)
  end

  it "serializes a successful response with Errors null, matching the plugin's nil slice" do
    response = KrikriAwsSsm::Handshake::HandshakeResponsePayload.new(
      "1.0.0",
      [KrikriAwsSsm::Handshake::ProcessedClientAction.new(
        KrikriAwsSsm::ActionType::SESSION_TYPE, KrikriAwsSsm::ActionStatus::Success.value)],
      nil)
    assert_equal(
      %({"ClientVersion":"1.0.0","ProcessedClientActions":[{"ActionType":"SessionType",) +
      %("ActionStatus":1,"ActionResult":null,"Error":""}],"Errors":null}),
      response.to_json)
  end

  it "serializes Errors as an array when actions failed" do
    response = KrikriAwsSsm::Handshake::HandshakeResponsePayload.new(
      "1.0.0",
      [KrikriAwsSsm::Handshake::ProcessedClientAction.new(
        KrikriAwsSsm::ActionType::KMS_ENCRYPTION, KrikriAwsSsm::ActionStatus::Failed.value,
        nil, "nope")],
      ["nope"])
    json = JSON.parse(response.to_json)
    assert_equal ["nope"], json["Errors"].as_a.map(&.as_s)
    assert_equal 2, json["ProcessedClientActions"][0]["ActionStatus"].as_i
  end

  it "parses the agent's handshake request including KMS parameters" do
    request = KrikriAwsSsm::Handshake::HandshakeRequestPayload.from_json(
      %({"AgentVersion":"3.3.3572.0","RequestedClientActions":[) +
      %({"ActionType":"SessionType","ActionParameters":{"SessionType":"Standard_Stream","Properties":{}}},) +
      %({"ActionType":"KMSEncryption","ActionParameters":{"KMSKeyId":"key-1","Challenge":"Y2g="}}]}))
    assert_equal "3.3.3572.0", request.agent_version
    assert_equal 2, request.requested_client_actions.size
    assert_equal "KMSEncryption", request.requested_client_actions[1].action_type
    assert_equal "key-1", request.requested_client_actions[1].action_parameters.try(&.["KMSKeyId"]).try(&.as_s)
  end

  it "emits a null Challenge like the reference struct" do
    request = KrikriAwsSsm::Handshake::KMSEncryptionRequest.new("key-1")
    assert_equal %({"KMSKeyId":"key-1","Challenge":null}), request.to_json
  end

  it "parses KMSEncryptionRequest parameters and round-trips them" do
    request = KrikriAwsSsm::Handshake::KMSEncryptionRequest.from_json(
      %({"KMSKeyId":"key-1","Challenge":"Y2hhbGxlbmdl"}))
    assert_equal "key-1", request.kms_key_id
    assert_equal "Y2hhbGxlbmdl", request.challenge
    assert_equal %({"KMSKeyId":"key-1","Challenge":"Y2hhbGxlbmdl"}), request.to_json
  end

  it "parses SessionTypeRequest properties" do
    request = KrikriAwsSsm::Handshake::SessionTypeRequest.from_json(
      %({"SessionType":"Standard_Stream","Properties":{"runAsEnabled":true}}))
    assert_equal "Standard_Stream", request.session_type
    assert_equal true, request.properties.try(&.["runAsEnabled"]).try(&.as_bool)
  end

  it "parses HandshakeComplete's nanosecond duration and customer message" do
    complete = KrikriAwsSsm::Handshake::HandshakeCompletePayload.from_json(
      %({"HandshakeTimeToComplete":12345678,"CustomerMessage":"hi"}))
    assert_equal 12345678_i64, complete.handshake_time_to_complete
    assert_equal "hi", complete.customer_message
  end
end
