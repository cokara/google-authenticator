module GoogleAuthenticatorRails
  module Session
    module Persistence
      class TokenNotFound < StandardError; end

      def self.included(klass)
        klass.class_eval do
          extend  ClassMethods
          include InstanceMethods
        end
      end
    end

    module ClassMethods
      def find
        cookie = controller.cookies[cookie_key]
        if cookie
          token, identifier = parse_cookie(cookie).values_at(:token, primary_key)
          conditions = { klass.google_lookup_token => token, primary_key => identifier }
          record = __send__(finder, conditions).first
          session = new(record)
          session.valid? ? session : nil
        else
          nil
        end
      end

      def create(user)
        raise GoogleAuthenticatorRails::Session::Persistence::TokenNotFound if user.nil? || !user.respond_to?(user.class.google_lookup_token) || user.google_token_value.blank?
        controller.cookies[cookie_key] = create_cookie(user.google_token_value, user.send(primary_key))
        new(user)
      end

      def destroy
        controller.cookies.delete cookie_key
      end

      private
      def finder
        @_finder ||= klass.public_methods.include?(:where) ? :rails_3_finder : :rails_2_finder
      end

      def rails_3_finder(conditions)
        klass.where(conditions)
      end

      def rails_2_finder(conditions)
        klass.scoped(:conditions => conditions)
      end

      def klass
        @_klass ||= "#{self.to_s.sub("MfaSession", "")}".constantize
      end

      def primary_key
        @_primary_key ||= klass.primary_key.to_sym
      end

      def parse_cookie(cookie)
        token, id = cookie.split('::')
        { :token => token, primary_key => id }
      end

      def create_cookie(token, identifier)
        value = [token, identifier].join('::')
        options = GoogleAuthenticatorRails.cookie_options || {}
        options.merge(
          :value    => value,
          :expires  => GoogleAuthenticatorRails.time_until_expiration.from_now
        )
      end

      def cookie_key
        suffix = GoogleAuthenticatorRails.cookie_key_suffix || 'mfa_credentials'
        "#{klass.to_s.downcase}_#{suffix}"
      end
    end

    module InstanceMethods
      def valid?
        !record.nil?
      end
    end
  end
end
