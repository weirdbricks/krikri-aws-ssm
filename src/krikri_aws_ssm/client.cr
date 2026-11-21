require "json"
require "./aws_json"
require "./credentials"
require "./errors"
require "./settings"

module KrikriAwsSsm
  # What `StartSession`/`ResumeSession` return.
  struct SessionInfo
    getter session_id : String
    getter stream_url : String
    getter token_value : String

    def initialize(@session_id : String, @stream_url : String, @token_value : String)
    end

    def self.parse(json : JSON::Any, action : String) : SessionInfo
      session_id = json["SessionId"]?.try(&.as_s?)
      stream_url = json["StreamUrl"]?.try(&.as_s?)
      token_value = json["TokenValue"]?.try(&.as_s?)
      unless session_id && stream_url && token_value
        raise ProtocolError.new("#{action} response is missing SessionId, StreamUrl or TokenValue")
      end
      new(session_id, stream_url, token_value)
    end

    # Never print the token or URL: both are session secrets.
    def to_s(io : IO) : Nil
      io << "SessionInfo(#{@session_id})"
    end
  end

  # The SSM control plane: StartSession, ResumeSession, TerminateSession and
  # DescribeSessions, signed JSON 1.1.
  class Client
    getter settings : Settings

    def initialize(@settings : Settings, @chain : CredentialChain = CredentialChain.default,
                   @aws_json : AwsJson? = nil)
      @credentials = @settings.credentials
    end

    # Resolved credentials, reused for the data-channel SigV4 signature.
    def credentials : Credentials
      @credentials ||= @chain.resolve(@settings.profile)
    end

    def start_session : SessionInfo
      SessionInfo.parse(aws_json.call("StartSession", start_session_body), "StartSession")
    end

    # ResumeSession returns a fresh URL and token for the same session; the
    # caller re-opens the data channel with them.
    def resume_session(session_id : String) : SessionInfo
      SessionInfo.parse(aws_json.call("ResumeSession", session_body(session_id)), "ResumeSession")
    end

    # Idempotent: a session that already ended is not an error.
    def terminate_session(session_id : String) : Nil
      aws_json.call("TerminateSession", session_body(session_id))
      nil
    rescue SessionNotFound
      nil
    end

    def describe_sessions(state : String = "Active") : Array(JSON::Any)
      response = aws_json.call("DescribeSessions", %({"State":#{state.to_json}}))
      response["Sessions"]?.try(&.as_a?) || [] of JSON::Any
    end

    private def aws_json : AwsJson
      @aws_json ||= begin
        AwsJson.new(
          service: "ssm",
          region: @settings.region,
          credentials: credentials,
          endpoint_url: @settings.endpoint_url,
          retries: @settings.retries,
          allow_insecure_endpoint: @settings.allow_insecure_endpoint?,
          connect_timeout: @settings.connect_timeout,
          read_timeout: @settings.read_timeout,
        )
      end
    end

    private def start_session_body : String
      JSON.build do |json|
        json.object do
          json.field "Target", @settings.target
          if document = @settings.document
            json.field "DocumentName", document
          end
          unless @settings.parameters.empty?
            json.field "Parameters" do
              json.object do
                @settings.parameters.each do |name, values|
                  json.field name do
                    json.array { values.each { |value| json.string value } }
                  end
                end
              end
            end
          end
        end
      end
    end

    private def session_body(session_id : String) : String
      JSON.build do |json|
        json.object { json.field "SessionId", session_id }
      end
    end
  end
end
