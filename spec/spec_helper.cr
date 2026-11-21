require "minitest/autorun"
require "http/server"
require "../src/krikri-aws-ssm"
require "../src/krikri_aws_ssm/testing/sigv4_verifier"
require "../src/krikri_aws_ssm/testing/fake_gateway"

# A tiny capture-and-reply HTTP server for control-plane specs.
class TestHttpServer
  getter port : Int32
  getter requests = Channel(HTTP::Request).new(16)
  @server : HTTP::Server

  def initialize(&handler : HTTP::Request -> TestHttpResponse)
    @server = HTTP::Server.new do |context|
      request = context.request
      body = request.body.try(&.gets_to_end) || ""
      captured = HTTP::Request.new(request.method, request.resource, request.headers, body)
      @requests.send(captured)
      reply = handler.call(captured)
      context.response.status_code = reply.status
      reply.headers.each do |name, values|
        values.each { |value| context.response.headers.add(name, value) }
      end
      context.response.print(reply.body)
    end
    @port = @server.bind_tcp("127.0.0.1", 0).port
    spawn { @server.listen }
  end

  def url : String
    "http://127.0.0.1:#{@port}"
  end

  def next_request : HTTP::Request
    @requests.receive
  end

  def close : Nil
    @server.close
  end
end

struct TestHttpResponse
  getter status : Int32
  getter body : String
  getter headers : HTTP::Headers

  def initialize(@status : Int32 = 200, @body : String = "",
                 @headers : HTTP::Headers = HTTP::Headers{"Content-Type" => "application/x-amz-json-1.1"})
  end
end

def receive_with_timeout(channel : Channel(T), timeout : Time::Span = 3.seconds) : T forall T
  select
  when value = channel.receive
    value
  when timeout(timeout)
    raise "timed out waiting for a channel value"
  end
end

def wait_until(timeout : Time::Span = 2.seconds, &) : Bool
  deadline = Time.monotonic + timeout
  while Time.monotonic < deadline
    return true if yield
    sleep 10.milliseconds
  end
  false
end

def read_with_timeout(session : KrikriAwsSsm::Session, timeout : Time::Span = 3.seconds) : KrikriAwsSsm::Output?
  channel = Channel(KrikriAwsSsm::Output?).new(1)
  spawn { channel.send(session.read?) }
  select
  when value = channel.receive
    value
  when timeout(timeout)
    raise "timed out waiting for session output"
  end
end

def read_required(session : KrikriAwsSsm::Session, timeout : Time::Span = 3.seconds) : KrikriAwsSsm::Output
  read_with_timeout(session, timeout) || raise "session closed before output arrived"
end
