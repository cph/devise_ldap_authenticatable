require 'devise_ldap_authenticatable/strategy'

module Devise
  module Models
    # LDAP Module, responsible for validating the user credentials via LDAP.
    #
    # Examples:
    #
    #    User.authenticate('email@test.com', 'password123')  # returns authenticated user or nil
    #    User.find(1).valid_password?('password123')         # returns true/false
    #
    module LdapAuthenticatable
      extend ActiveSupport::Concern
      
      def login_with
        @login_with ||= Devise.mappings[self.class.to_s.underscore.to_sym].to.authentication_keys.first
        self[@login_with]
      end
      
      def ldap_groups
        Devise::LdapAdapter.get_groups(login_with)
      end
      
      def in_ldap_group?(group_name, group_attribute = LdapAdapter::DEFAULT_GROUP_UNIQUE_MEMBER_LIST_KEY)
        Devise::LdapAdapter.in_ldap_group?(login_with, group_name, group_attribute)
      end
      
      def ldap_dn
        Devise::LdapAdapter.get_dn(login_with)
      end
      
      def ldap_get_param(login_with, param)
        Devise::LdapAdapter.get_ldap_param(login_with,param)
      end
      
      #
      # callbacks
      #
      
      # # Called before the ldap record is saved automatically
      # def ldap_before_save
      # end
      
      module ClassMethods
        # Authenticate a user based on configured attribute keys. Returns the
        # authenticated user if it's valid or nil.
        def authenticate_with_ldap(attributes={})
          auth_key = self.authentication_keys.first
          return nil unless attributes[auth_key].present?
          
          auth_key_value = (self.case_insensitive_keys || []).include?(auth_key) ? attributes[auth_key].downcase : attributes[auth_key]
          
          ldap_connection = Devise::LdapAdapter::LdapConnect.new(
            login: auth_key_value,
            password: attributes[:password],
            ldap_auth_username_builder: ::Devise.ldap_auth_username_builder,
            admin: ::Devise.ldap_use_admin_to_bind )
          return nil unless ldap_connection.authorized?
          
          entry = find_ldap_entry(ldap_connection, auth_key_value)
          resource = find_for_ldap_authentication(attributes, entry)
          resource = create_from_ldap_entry(attributes, entry) if resource.nil? && ::Devise.ldap_create_user
          resource
        end

        def find_ldap_entry(ldap_connection, auth_key_value)
          ldap_connection.search_for_login
        end

        def find_for_ldap_authentication(attributes, entry)
          auth_key = self.authentication_keys.first
          auth_key_value = (self.case_insensitive_keys || []).include?(auth_key) ? attributes[auth_key].downcase : attributes[auth_key]
          
          where(auth_key => auth_key_value).first
        end

        def self.create_from_ldap_entry(attributes, entry)
          auth_key = self.authentication_keys.first
          auth_key_value = (self.case_insensitive_keys || []).include?(auth_key) ? attributes[auth_key].downcase : attributes[auth_key]
          
          resource = new
          resource[auth_key] = auth_key_value
          resource.password = attributes[:password]
          resource.ldap_before_save if resources.respond_to?(:ldap_before_save)
          resource.tap(&:save)
        end

        def update_with_password(resource)
          puts "UPDATE_WITH_PASSWORD: #{resource.inspect}"
        end

      end
    end
  end
end
