# coding: utf-8
require_relative 'lib/ObjectPwnStream'
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)


Gem::Specification.new do |spec|
  spec.name          = "ObjectPwnStream"
  spec.version       = ObjectPwnStream::VERSION
  spec.authors       = "hakivvi"
  spec.email         = "hakivvi@gmail.com"

  spec.summary       = %q{a Ruby implementation for ObjectInputStream and ObjectOutputStream to ease JAVA deserialization exploitation.}
  spec.description   = %q{a Ruby implementation of Java's ObjectInputStream and ObjectOutputStream, to ease the process of Java deserialization exploitation.}
  spec.homepage      = "https://github.com/hakivvi/ObjectPwnStream"
  spec.license       = "MIT"

  spec.required_ruby_version = '>= 3.0.0'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  # if spec.respond_to?(:metadata)
  #   spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"
  # else
  #   raise "RubyGems 2.0 or newer is required to protect against " \
  #     "public gem pushes."
  # end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
