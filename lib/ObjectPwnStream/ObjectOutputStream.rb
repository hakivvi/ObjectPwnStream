require_relative 'Constants'
require_relative 'ObjectInputStream'
require_relative 'PwnStream'

module ObjectPwnStream
  module  ObjectOutputStream
    include Constants

    def open_output_stream
      write_stream_header(*[Constants::STREAM_MAGIC, Constants::STREAM_VERSION])
    end

    def write_int(v, signed: false)
      length = 4
      write_block_header(Constants::TC_BLOCKDATA, length)
      template = (signed ? "l>" : "L>")
      @outstream.write([v].pack(template))
      @outstream.flush
    end

    def write_short(v, signed: false)
      v &= 0xFFFF
      length = 2
      write_block_header(Constants::TC_BLOCKDATA, length)
      template = (signed ? "s>" : "S>")
      @outstream.write([v].pack(template))
      @outstream.flush
    end

    def write_char(char)
      write_short(char.unpack("U")[0])
    end

    def write_chars(str)
      conv = Encoding::Converter.new("utf-8", "utf-16")
      data = conv.convert(str)
      write_block_header(Constants::TC_BLOCKDATA, data.bytesize)
      @outstream.write(data)
      @outstream.flush
    end

    def write_byte(byte)
      write_block_header(Constants::TC_BLOCKDATA, 0x1)
      @outstream.putc(byte)
      @outstream.flush
    end

    def write_bytes(bytes)
      write_block_header(Constants::TC_BLOCKDATA, bytes.size)
      bytes.each {@outstream.putc(_1)}
      @outstream.flush
    end

    def write_utf(str)
      utf_size = str.bytesize
      write_block_header(Constants::TC_BLOCKDATA, utf_size+2)
      @outstream.write([utf_size].pack("S>"))
      @outstream.write(str)
      @outstream.flush

    end

    def write_boolean(bool)
      write_block_header(Constants::TC_BLOCKDATA, 1)
      @outstream.putc(bool ? 0x1 : 0x0)
      @outstream.flush
    end

    def write_float(float)
      write_block_header(Constants::TC_BLOCKDATA, 4)
      @outstream.write([float].pack("g"))
      @outstream.flush
    end

    def write_double(double)
      write_block_header(Constants::TC_BLOCKDATA, 8)
      @outstream.write([double].pack("G"))
      @outstream.flush
    end

    def write_long(long, signed: false)
      write_block_header(Constants::TC_BLOCKDATA, 8)
      template = signed ? "q>" : "Q>"
      @outstream.write([long].pack(template))
      @outstream.flush
    end

    def reset!
      @outstream.putc(Constants::TC_RESET)
      @outstream.flush
    end

    def write_object(payload_path: nil, payload: nil, ysoserial: false)
      if ysoserial
        @outstream.write(@payload)
        @outstream.flush
      elsif payload
        ObjectInputStream.check_stream_header(payload[...4].unpack("S>*"), provided: true)
        @outstream.write(payload[4..])
        @outstream.flush
      elsif payload_path
        pf = File.open(payload_path, "rb")
        ObjectInputStream.check_stream_header(pf.read(4).unpack("S>*"), provided: true)
        @outstream.write(pf.read(pf.size-4))
        @outstream.flush
      end
    end

    private
    def write_stream_header(block, version)
      @outstream.write([block, version].pack("S>S>"))
      @outstream.flush
  end

    def write_block_header(block, length)
      @outstream.write([block, length].pack("CC"))
      @outstream.flush
    end
  end
end