require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Suunto < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site: 'https://cloudapi-oauth.suunto.com',
        authorize_url: '/oauth/authorize',
        token_url: '/oauth/token'
      }

      uid { raw_info['user'] }

      extra do
        { raw_info: raw_info }
      end

      def request_phase
        options[:authorize_params] = client_params.merge(options[:authorize_params])
        super
      end

      def callback_url	
        full_host + script_name + callback_path	
      end

      def auth_hash
        OmniAuth::Utils.deep_merge(super, client_params.merge({grant_type: 'authorization_code'}))
      end

      def raw_info
        @raw_info ||= access_token.params
      end

      private

      def client_params
        {
          client_id: options[:client_id],
          redirect_uri: callback_url,
          response_type: 'code'
        }
      end
    end
  end
end
