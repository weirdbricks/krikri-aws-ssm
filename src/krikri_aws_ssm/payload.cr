require "json"

module KrikriAwsSsm
  # Message types, pinned from `src/message/clientmessage.go`.
  module MessageType
    INPUT_STREAM_DATA  = "input_stream_data"
    OUTPUT_STREAM_DATA = "output_stream_data"
    ACKNOWLEDGE        = "acknowledge"
    CHANNEL_CLOSED     = "channel_closed"
    START_PUBLICATION  = "start_publication"
    PAUSE_PUBLICATION  = "pause_publication"

    # Messages whose payload digest the reference implementation does not
    # validate (`ClientMessage.Validate` returns early for these).
    def self.digest_exempt?(type : String) : Bool
      type == START_PUBLICATION || type == PAUSE_PUBLICATION
    end
  end

  # Payload types, pinned from `src/message/clientmessage.go` and the agent's
  # `agent/session/contracts/model.go`.
  enum PayloadType : UInt32
    Undefined            =  0
    Output               =  1
    Error                =  2
    Size                 =  3
    Parameter            =  4
    HandshakeRequest     =  5
    HandshakeResponse    =  6
    HandshakeComplete    =  7
    EncChallengeRequest  =  8
    EncChallengeResponse =  9
    Flag                 = 10
    StdErr               = 11
    ExitCode             = 12
  end

  # Header flag bits: bit 0 SYN, bit 1 FIN.
  module Flags
    NONE = 0_u64
    SYN  = 1_u64
    FIN  = 2_u64
    # Acknowledgements always carry SYN | FIN.
    ACK = SYN | FIN
  end

  module ActionType
    KMS_ENCRYPTION = "KMSEncryption"
    SESSION_TYPE   = "SessionType"
  end

  enum ActionStatus : Int32
    Success     = 1
    Failed      = 2
    Unsupported = 3
  end

  module SessionType
    STANDARD_STREAM          = "Standard_Stream"
    INTERACTIVE_COMMANDS     = "InteractiveCommands"
    NON_INTERACTIVE_COMMANDS = "NonInteractiveCommands"
    PORT                     = "Port"
  end

  # Acknowledge body, pinned from `AcknowledgeContent`.
  struct AcknowledgeContent
    include JSON::Serializable

    @[JSON::Field(key: "AcknowledgedMessageType")]
    getter message_type : String

    @[JSON::Field(key: "AcknowledgedMessageId")]
    getter message_id : String

    @[JSON::Field(key: "AcknowledgedMessageSequenceNumber")]
    getter sequence_number : Int64

    @[JSON::Field(key: "IsSequentialMessage")]
    getter? sequential : Bool

    def initialize(@message_type : String, @message_id : String, @sequence_number : Int64,
                   @sequential : Bool = true)
    end
  end

  # Channel-closed body, pinned from `ChannelClosed`. `CreatedDate` is a string
  # in the reference implementation, so it is kept as one here.
  struct ChannelClosedContent
    include JSON::Serializable

    @[JSON::Field(key: "MessageId")]
    getter message_id : String?

    @[JSON::Field(key: "CreatedDate")]
    getter created_date : String?

    @[JSON::Field(key: "DestinationId")]
    getter destination_id : String?

    @[JSON::Field(key: "SessionId")]
    getter session_id : String?

    @[JSON::Field(key: "MessageType")]
    getter message_type : String?

    @[JSON::Field(key: "SchemaVersion")]
    getter schema_version : Int32?

    @[JSON::Field(key: "Output")]
    getter output : String?
  end

  # Terminal size body (`SizeData`), payload type 3.
  struct SizeContent
    include JSON::Serializable

    @[JSON::Field(key: "cols")]
    getter cols : UInt32

    @[JSON::Field(key: "rows")]
    getter rows : UInt32

    def initialize(@cols : UInt32, @rows : UInt32)
    end
  end
end
