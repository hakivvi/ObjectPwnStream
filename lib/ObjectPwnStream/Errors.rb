module ObjectPwnStream
  module Errors
    class StreamHeaderError < StandardError
      def message()="received an invalid stream header from the server."
    end

    class InvalidStreamReset < StandardError
      def message()="received an invalid reset sequence from the server."
    end

    class PayloadStreamHeaderError < StandardError
      def message()="the signed: false serialized payload has an invalid stream header."
    end

    class YsoserialGenerateError < StandardError
      def initialize(cmd)
        super("Ysoserial returned an empty string, make sure the arguments are correct.\n\tthis command was run: #{cmd}")
      end
    end

    class YsoserialPayloadCorruptedError < StandardError
      def message()="the payload returned by Ysoserial is corrupted."
    end
  end
end