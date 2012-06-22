$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "authlogic_api/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "authlogic_api"
  s.version     = AuthlogicApi::VERSION
  s.authors     = ["Jon Bringhurst"]
  s.email       = ["jon@bringhurst.org"]
  s.homepage    = "TODO"
  s.summary     = "TODO: Summary of AuthlogicApi."
  s.description = "TODO: Description of AuthlogicApi."

  s.files = Dir["{app,config,db,lib}/**/*"] + ["Rakefile", "README.rdoc"]
  s.test_files = Dir["test/**/*"]

  s.add_dependency "rails", "~> 3.2.6"
  s.add_dependency "authlogic"

  s.add_development_dependency "sqlite3"
end
