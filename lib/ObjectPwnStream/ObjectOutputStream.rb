require_relative 'Constants'
require_relative 'ObjectInputStream'
require_relative 'PwnStream'

module ObjectPwnStream
  module  ObjectOutputStream
    include Constants

    def open_output_stream
      write_stream_header(*[Constants::STREAM_MAGIC, Constants::STREAM_VERSION])
    end

    def write_int(v, signed=false)
      length = 4
      write_block_header(Constants::TC_BLOCKDATA, length)
      template = (signed ? "l>" : "L>")
      @socket.write([v].pack(template))
      @socket.flush
    end

    def write_short(v, signed=false)
      v &= 0xFFFF
      length = 2
      write_block_header(Constants::TC_BLOCKDATA, length)
      template = (signed ? "s>" : "S>")
      @socket.write([v].pack(template))
      @socket.flush
    end

    def write_char(char)
      write_short(char.unpack("U")[0])
    end

    def write_chars(str)
      conv = Encoding::Converter.new("utf-8", "utf-16")
      data = conv.convert(str)
      write_block_header(Constants::TC_BLOCKDATA, data.bytesize)
      @socket.write(data)
      @socket.flush
    end

    def write_byte(byte)
      write_block_header(Constants::TC_BLOCKDATA, 0x1)
      @socket.putc(byte)
      @socket.flush
    end

    def write_bytes(bytes)
      write_block_header(Constants::TC_BLOCKDATA, bytes.size)
      bytes.each {@socket.putc(_1)}
      @socket.flush
    end

    def write_utf(str)
      utf_size = str.bytesize
      write_block_header(Constants::TC_BLOCKDATA, utf_size+2)
      @socket.write([utf_size].pack("S>"))
      @socket.write(str)
      @socket.flush

    end

    def write_boolean(bool)
      write_block_header(Constants::TC_BLOCKDATA, 1)
      @socket.putc(bool ? 0x1 : 0x0)
      @socket.flush
    end

    def write_float(float)
      write_block_header(Constants::TC_BLOCKDATA, 4)
      @socket.write([float].pack("g"))
      @socket.flush
    end

    def write_double(double)
      write_block_header(Constants::TC_BLOCKDATA, 8)
      @socket.write([double].pack("G"))
      @socket.flush
    end

    def write_long(long, signed=false)
      write_block_header(Constants::TC_BLOCKDATA, 8)
      template = signed ? "q>" : "Q>"
      @socket.write([long].pack(template))
      @socket.flush
    end

    def reset!
      @socket.putc(Constants::TC_RESET)
      @socket.flush
    end

    def write_object(payload_path: nil, payload: nil, ysoserial: false)
      if ysoserial
        @socket.write(@payload)
        @socket.flush
      elsif payload
        ObjectInputStream.check_stream_header(payload[...4].unpack("S>*"), provided: true)
        @socket.write(payload[4..])
        @socket.flush
      elsif payload_path
        pf = File.open(payload_path, "rb")
        ObjectInputStream.check_stream_header(pf.read(4).unpack("S>*"), provided: true)
        @socket.write(pf.read(pf.size-4))
        @socket.flush
      end
    end

    private
    def write_stream_header(block, version)
      @socket.write([block, version].pack("S>S>"))
      @socket.flush
    end

    def write_block_header(block, length)
      @socket.write([block, length].pack("CC"))
      @socket.flush
    end
  end
end