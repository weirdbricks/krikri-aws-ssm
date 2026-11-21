require "minitest/autorun"
require "http/server"
require "../src/krikri-aws-ssm"
require "../src/krikri_aws_ssm/testing/sigv4_verifier"

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
