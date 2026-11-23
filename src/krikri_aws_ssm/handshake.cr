require "json"
require "./payload"

module KrikriAwsSsm
  # Handshake payloads, pinned field-for-field from
  # `src/message/handshakemessage.go` (client) and the agent's
  # `agent/session/contracts/model.go`.
  module Handshake
    @[JSON::Serializable::Options(emit_nulls: true)]
    struct RequestedClientAction
      include JSON::Serializable

      @[JSON::Field(key: "ActionType")]
      getter action_type : String

      @[JSON::Field(key: "ActionParameters")]
      getter action_parameters : JSON::Any?

      def initialize(@action_type : String, @action_parameters : JSON::Any? = nil)
      end
    end

    struct HandshakeRequestPayload
      include JSON::Serializable

      @[JSON::Field(key: "AgentVersion")]
      getter agent_version : String

      @[JSON::Field(key: "RequestedClientActions")]
      getter requested_client_actions : Array(RequestedClientAction)

      def initialize(@agent_version : String, @requested_client_actions : Array(RequestedClientAction))
      end
    end

    @[JSON::Serializable::Options(emit_nulls: true)]
    struct ProcessedClientAction
      include JSON::Serializable

      @[JSON::Field(key: "ActionType")]
      getter action_type : String

      # Go's ActionStatus is an int; it must serialize as 1/2/3, not a name.
      @[JSON::Field(key: "ActionStatus")]
      getter action_status : Int32

      @[JSON::Field(key: "ActionResult")]
      getter action_result : JSON::Any?

      @[JSON::Field(key: "Error")]
      getter error : String

      def initialize(@action_type : String, @action_status : Int32,
                     @action_result : JSON::Any? = nil, @error : String = "")
      end
    end

    @[JSON::Serializable::Options(emit_nulls: true)]
    struct HandshakeResponsePayload
      include JSON::Serializable

      @[JSON::Field(key: "ClientVersion")]
      getter client_version : String

      @[JSON::Field(key: "ProcessedClientActions")]
      getter processed_client_actions : Array(ProcessedClientAction)

      # A nil slice marshals as `null` in the reference plugin on success.
      @[JSON::Field(key: "Errors")]
      getter errors : Array(String)?

      def initialize(@client_version : String,
                     @processed_client_actions : Array(ProcessedClientAction),
                     @errors : Array(String)? = nil)
      end
    end

    struct HandshakeCompletePayload
      include JSON::Serializable

      # Go `time.Duration`: nanoseconds as a JSON number.
      @[JSON::Field(key: "HandshakeTimeToComplete")]
      getter handshake_time_to_complete : Int64?

      @[JSON::Field(key: "CustomerMessage")]
      getter customer_message : String?
    end

    @[JSON::Serializable::Options(emit_nulls: true)]
    struct SessionTypeRequest
      include JSON::Serializable

      @[JSON::Field(key: "SessionType")]
      getter session_type : String

      @[JSON::Field(key: "Properties")]
      getter properties : JSON::Any?

      def initialize(@session_type : String, @properties : JSON::Any? = nil)
      end
    end

    @[JSON::Serializable::Options(emit_nulls: true)]
    struct KMSEncryptionRequest
      include JSON::Serializable

      @[JSON::Field(key: "KMSKeyId")]
      getter kms_key_id : String

      @[JSON::Field(key: "Challenge")]
      getter challenge : String?

      def initialize(@kms_key_id : String, @challenge : String? = nil)
      end
    end
  end
end
