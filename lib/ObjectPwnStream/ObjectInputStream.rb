require_relative 'Constants'
require_relative 'Errors'

module ObjectPwnStream
  module ObjectInputStream
    include Constants
    include Errors

    def open_input_stream
      check_stream_header(read_stream_header)
    end

    def read_int(signed=false)
      _, length = read_block_header
      template = (signed ? "l>" : "L>")
      @socket.read(length).unpack(template)[0]
      # to_signed(hex.to_i(16))
    end

    def read_short(signed=false)
      _, length = read_block_header
      template = (signed ? "s>" : "S>")
      @socket.read(length).unpack(template)[0]
    end

    def read_char
      [read_short].pack("U")
    end

    def read_chars
      _, length = read_block_header
      @socket.read(length).unpack("S>*").pack("U*")
    end

    def read_byte
      read_block_header
      @socket.getbyte
    end

    def read_bytes
      _, length = read_block_header
      @socket.read(length).unpack("C*")
    end

    def read_utf
      _, block_length = read_block_header
      length = @socket.read(2).unpack("S>")[0]
      @socket.read(length).unpack("U*").pack("U*")
    end

    def read_boolean
      read_block_header
      bool = @socket.getbyte
      bool != 0
    end

    def handle_reset
      check_stream_reset(@socket.getbyte)
    end

    def read_float
      _, length = read_block_header
      @socket.read(length).unpack("g")[0]
    end

    def read_double
      _, length = read_block_header
      @socket.read(length).unpack("G")[0]
    end

    def read_long(signed=false)
      _, length = read_block_header
      template = signed ? "q>" : "Q>"
      @socket.read(length).unpack(template)[0]
    end

    def read_object
      bytes = [@socket.getbyte]
      while @socket.ready?
        bytes << @socket.getbyte
      end
      bytes.pack("C*")
    end

    private
    def read_stream_header
      @socket.read(4).unpack("S>S>")
    end

    def read_block_header
      block = @socket.getbyte
      if block.eql?(Constants::TC_BLOCKDATA)
        length = @socket.getbyte
      elsif block.eql?(Constants::TC_BLOCKDATALONG)
        length = @socket.read(4).unpack("I>")[0]
      end
      [block, length]
    end

    def check_stream_header(header, provided=nil)
      unless header.first.eql?(Constants::STREAM_MAGIC) && header.last.eql?(Constants::STREAM_VERSION)
        raise provided.nil? ? Errors::StreamHeaderError : !provided ? Errors::YsoserialPayloadCorruptedError : Errors::PayloadStreamHeaderError
      end
    end

    def check_stream_reset(reset)
      unless reset.eql?(Constants::TC_RESET)
        raise Errors::InvalidStreamReset
      end
    end

    module_function(:check_stream_header)
  end
end