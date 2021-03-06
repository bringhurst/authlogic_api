require "authlogic_api/acts_as_authentic"
require "authlogic_api/session"
require "authlogic_api/nonce"

ActiveRecord::Base.send(:include, AuthlogicApi::ActsAsAuthentic)
Authlogic::Session::Base.send(:include, AuthlogicApi::Session)