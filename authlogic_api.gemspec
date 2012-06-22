$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "authlogic_api/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "authlogic_api"
  s.version     = AuthlogicApi::VERSION
  s.authors     = ["Jon Bringhurst"]
  s.email       = ["jon@bringhurst.org"]
  s.homepage    = "http://github.com/fintler/authlogic_api"
  s.summary     = "Developer API key plugin for authlogic."
  s.description = "This is a plugin for Authlogic to allow API requests to be authenticated automatically by using an api_key/signature mechanism. The plugin will automatically compute the hashed sum of the request params and compare it to the passed signature."

  s.files = Dir["{app,config,db,lib}/**/*"] + ["Rakefile", "README.rdoc", "LICENSE"]
  s.test_files = Dir["test/**/*"]

  s.add_dependency "rails", "~> 3.2.6"
  s.add_dependency "authlogic"

  s.add_development_dependency "sqlite3"
end
