module AuthlogicApi
  # Note that because authenticating through an API is a single access authentication, many of the magic columns are
  # not updated. Here is a list of the magic columns with their update state:
  #   login_count           Never increased because there's no explicit login
  #   failed_login_count    Updated. That is every signature mismatch will increase this value.
  #   last_request_at       Updated.
  #   current_login_at      Left unchanged.
  #   last_login_at         Left unchanged.
  #   current_login_ip      Left unchanged.
  #   last_login_ip         Left unchanged.
  #
  # AuthlogicApi adds some more magic columns to fill the gap, here they are:
  #   request_count         Increased every time a request is made.
  #                         Counts also invalid requests, so this is the total count.
  #                         To have the count of valid requests use : request_count - failed_login_count
  #   last_request_ip       Updates with the request remote_ip for each request.
  #
  module Session
    def self.included(klass)
      klass.class_eval do
        extend Config
        include Methods
      end
    end
    
    module Config
      # Defines the param key name where the api_key will be received.
      #
      # You *must* define this to enable API authentication.
      #
      # * <tt>Default:</tt> nil
      # * <tt>Accepts:</tt> String
      def api_key_param(value = nil)
        rw_config(:api_key_param, value, nil)
      end
      alias_method :api_key_param=, :api_key_param

      # Defines the param key name where the signature will be received.
      #
      # * <tt>Default:</tt> 'signature'
      # * <tt>Accepts:</tt> String
      def api_signature_param(value = nil)
        rw_config(:api_signature_param, value, 'signature')
      end
      alias_method :api_signature_param=, :api_signature_param
      
      # To be able to authenticate the incoming request, AuthlogicApi has to find a valid api_key in your system.
      # This config setting let's you choose which method to call on your model to get an application model object.
      #
      # Let's say you have an ApplicationSession that is authenticating an ApplicationAccount. By default ApplicationSession will
      # call ApplicationAccount.find_by_api_key(api_key).
      #
      # * <tt>Default:</tt> :find_by_api_key
      # * <tt>Accepts:</tt> Symbol or String
      def find_by_api_key_method(value = nil)
        rw_config(:find_by_api_key_method, value, :find_by_api_key)
      end
      alias_method :find_by_api_key_method=, :find_by_api_key_method

      # The generation of the request signature is selectable by this config setting.
      # You may either directly override the Methods#generate_api_signature method on the Session class,
      # or use this config to select another method.
      #
      # The default implementation of #generate_api_signature is the following:
      #   def generate_api_signature(secret)
      #     Digest::SHA512.hexdigest(build_api_payload + secret)
      #   end
      #
      # Note the call to #build_api_payload, which is another method you may override to customize
      # your own way of building the payload that will be signed.
      # WARNING: The current implementation of #build_api_payload is Rails oriented. Override if you use another framework.
      #
      # * <tt>Default:</tt> :generate_api_signature
      # * <tt>Accepts:</tt> Symbol
      def generate_api_signature_method(value = nil)
        rw_config(:generate_api_signature_method, value, :generate_api_signature)
      end
      alias_method :generate_api_signature_method=, :generate_api_signature_method
      
      # Defines the param key name where the nonce will be received.
      #
      # * <tt>Default:</tt> 'nonce'
      # * <tt>Accepts:</tt> String
      def api_nonce_param(value = nil)
        rw_config(:api_nonce_param, value, 'nonce')
      end
      alias_method :api_nonce_param=, :api_nonce_param
      
      # Signature validation is helpful for authenticating users, but without single-use token (nonce) validation,
      # signature validation will not be sufficient to prevent replay attacks.  That is to say, if the URL:
      # http://example.com/foo?bar=baz&api_key=123&signature=abc is valid, it will grant access to any user
      # that visits the static URL, even if that user does not know the secret that was originally used to generate the
      # signature. This problem can be overcome by adding additional, expiring parameters to the URL before generating 
      # the signature.  
      #
      # The three possible values of nonce_validation are:
      # * <tt>nil</tt> - (Default) Nonce validation will not be used, and the API will be vulnerable to replay attacks. 
      # * <tt>:timeout</tt> - a nonce parameter containing a request timestamp is required.  Requests that are timestamped 
      #   earlier than N{default:600} seconds ago are rejected.  This method reduces, but does not eliminate, the threat of
      #   replay attacks.
      # * <tt>:active_record</tt> - a nonce paramter containing a request timestamp and a unique random salt is required.
      #   Requests are discarded if the timestamp is too old, otherwise the application checks the database to see if the salt
      #   has been used before.  Only if the salt is unique and is stored to prevent reuse is the request permitted.  This method
      #   largely prevents replay attacks. 
      # 
      # If set to :active_record, consider using or revising the following:
      #
      # class Nonce < ActiveRecord::Base
      #   include AuthlogicApi::Nonce
      # end
      #
      # class CreateNonces < ActiveRecord::Migration
      #   def self.up
      #     create_table :nonces do |t|
      #       t.integer :timestamp
      #       t.string :salt
      #     end
      #     add_index :nonces, [:timestamp, :salt]
      #   end
      #
      #   def self.down
      #     drop_table :nonces
      #   end
      # end
      #
      def nonce_validation(value = nil)
        rw_config(:nonce_validation, value, nil)
      end
      alias_method :nonce_validation=, :nonce_validation
      
      # Defines the maximum age of a request's nonce timestamp before that request is automatically denied.
      #
      # * <tt>Default:</tt> 600
      # * <tt>Accepts:</tt> Integer
      def nonce_validation_timeout(value = nil)
        rw_config(:nonce_validation_timeout, value, 600)
      end
      alias_method :nonce_validation_timeout=, :nonce_validation_timeout
      
      # Defines a custom method for validating a nonce.
      #
      # If using nonce validation, the default expectation is for the request to provide a single nonce parameter
      # which is a Base64 encoded string of colon-separated values.  It is assumed that the first value is a 
      # timestamp in integer format (as seconds since epoch), and that the second value is the unique salt; however,
      # the unique salt is only required if nonce_validation is set to :active_record.
      #
      # For example, a method to create the nonce parameter might resemble:
      #
      #   def generate_nonce(time = Time.now)
      #     Base64.encode64("#{time.to_i}:#{ActiveSupport::SecureRandom.hex(16)}").gsub("\n", '')
      #   end
      #
      # * <tt>Default:</tt> :validate_nonce
      # * <tt>Returns:</tt> Boolean
      def validate_nonce_method(value = nil)
        rw_config(:validate_nonce_method, value, :validate_nonce)
      end
      alias_method :validate_nonce_method=, :validate_nonce_method
    end
    
    module Methods
      def self.included(klass)
        klass.class_eval do
          attr_accessor :single_access
          persist :persist_by_api, :if => :authenticating_with_api?
          validate :validate_by_api, :if => :authenticating_with_api?
          after_persisting :set_api_magic_columns, :if => :authenticating_with_api?
        end
      end
      
      # Hooks into credentials to print out meaningful credentials for API authentication.
      def credentials
        authenticating_with_api? ? {:api_key => api_key} : super
      end
      
      private
        def persist_by_api
          self.unauthorized_record = search_for_record(self.class.find_by_api_key_method, api_key)
          self.single_access = valid?
        end

        def validate_by_api          
          self.attempted_record = search_for_record(self.class.find_by_api_key_method, api_key)
          if attempted_record.blank?
            generalize_credentials_error_messages? ?
              add_general_credentials_error :
              errors.add(api_key_param, I18n.t('error_messages.api_key_not_found', :default => "is not valid"))
            return
          end
          
          unless validate_nonce(api_nonce, nonce_validation_timeout)
            self.invalid_password = true  # magic columns housekeeping
            generalize_credentials_error_messages? ?
            add_general_credentials_error :
            errors.add("Nonce", I18n.t('error_messages.invalid_nonce', :default => "is not valid"))
            return
          end
          
          signature = send(self.class.generate_api_signature_method, attempted_record.send(klass.api_secret_field))
          if api_signature != signature
            self.invalid_password = true  # magic columns housekeeping
            generalize_credentials_error_messages? ?
              add_general_credentials_error :
              errors.add(api_signature_param, I18n.t('error_messages.invalid_signature', :default => "is not valid"))
            return
          end
        end

        def authenticating_with_api?
          !api_key.blank? && !api_signature.blank?
        end
      
        def api_key
          controller.params[api_key_param]
        end

        def api_signature
          controller.params[api_signature_param]
        end
      
        def api_nonce
          controller.params[api_nonce_param]
        end
        
        def api_key_param
          self.class.api_key_param
        end
      
        def api_signature_param
          self.class.api_signature_param
        end
        
        def api_nonce_param
          self.class.api_nonce_param
        end
        
        def nonce_validation
          self.class.nonce_validation
        end
        
        def nonce_validation_timeout
          self.class.nonce_validation_timeout
        end
        
        # WARNING: Rails specfic way of building payload
        def build_api_payload
          request = controller.request
          if request.post? || request.put?
            request.raw_post
          else
            params = request.query_parameters.reject {|key, value| key.to_s == api_signature_param}
            params.sort_by {|key, value| key.to_s.underscore}.join('')
          end
        end
      
        def generate_api_signature(secret, time = Time.now)
          Digest::SHA512.hexdigest(build_api_payload + secret)
        end
        
        def validate_nonce(n, seconds_to_timeout = 600)
          return false if n.blank?
           t = Base64.decode64(n).split(":")[0].to_i
           nv = Base64.decode64(n).split(":")[1]
          case nonce_validation
            when :timeout
              return (t - Time.now.to_i).abs <= seconds_to_timeout
            when :active_record
              return Nonce.validate_single_use(nv, t, seconds_to_timeout)
            else
              return true # not using nonce validation
          end
        end
        
        def generate_nonce(time = Time.now)
          Base64.encode64("#{time.to_i}:#{ActiveSupport::SecureRandom.hex(16)}").gsub("\n", '')
        end
        
        def set_api_magic_columns
          record.request_count = (record.request_count.blank? ? 1 : record.request_count + 1) if record.respond_to?(:request_count)
          record.last_request_ip = controller.request.remote_ip if record.respond_to?(:last_request_ip)
        end

    end
  end
end
