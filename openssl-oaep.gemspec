# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'openssl/oaep/version'

Gem::Specification.new do |spec|
  spec.name          = "openssl-oaep"
  spec.version       = Openssl::Oaep::VERSION
  spec.authors       = ["Yui Terashima"]
  spec.email         = ["terashi@freee.co.jp"]

  spec.summary       = "Add support for OAEP with SHA2 and labels"
  spec.description   = "Minium extention to Ruby OpenSSL library to support OAEP with SHA2 and labels"
  spec.homepage      = "TODO: Put your gem's website or public repo URL here."
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
