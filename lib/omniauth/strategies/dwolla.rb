require 'omniauth-oauth2'
require 'dwolla'

#require 'dwolla-ruby'
# require '/Users/bryangoettsch/.rvm/gems/ruby-1.9.3-p125@tippable0.3/gems/dwolla-ruby-2.1.0/lib/dwolla/exceptions'

module OmniAuth
  module Strategies
    class Dwolla < OmniAuth::Strategies::OAuth2
      
      DEFAULT_SCOPE = 'accountinfofull'
      
      option :name, 'dwolla'
      option :client_options, {
        :site => 'https://www.dwolla.com',
        :authorize_url => '/oauth/v2/authenticate',
        :token_url => '/oauth/v2/token'
      }    

      uid { user['Id'] }

      info do
        prune!({
          'name'      => @user_info['Name'],
          'latitude'  => @user_info['Latitude'],
          'longitude' => @user_info['Longitude'],
          'city'      => @user_info['City'],
          'state'     => @user_info['State'],
          'type'      => @user_info['Type']
        })
      end

      def authorize_params
        super.tap do |params|
          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      private
        def user          
          ::Dwolla::token = access_token.token
          @user_info ||= ::Dwolla::Users.get()
        rescue ::Dwolla::DwollaError => e
          raise CallbackError.new(e, e.message)
        end

        def prune!(hash)
          hash.delete_if do |_, value| 
            prune!(value) if value.is_a?(Hash)
            value.nil? || (value.respond_to?(:empty?) && value.empty?)
          end
        end
     end
   end
end
