require "net/ldap"

module Devise
  module LDAP
    DEFAULT_GROUP_UNIQUE_MEMBER_LIST_KEY = 'uniqueMember'

    module Adapter

      def self.shared_connection
        begin
          Thread.current['ldap_connection_sharing_enabled'] = true
          yield
        ensure
          Thread.current['ldap_shared_connection'] = nil
          Thread.current['ldap_connection_sharing_enabled'] = false
        end
      end

      def self.ldap_config
        if ::Devise.ldap_config.is_a?(Proc)
          ldap_config = ::Devise.ldap_config.call
        else
          ldap_config = YAML.load(ERB.new(File.read(::Devise.ldap_config || "#{Rails.root}/config/ldap.yml")).result)[Rails.env]
        end
        ldap_config
      end

      def self.get_ldap_domain_from_dn(dn)
        lower_dn = dn.downcase
        ldap_config = self.ldap_config
        if ldap_config.is_a?(Hash)
          return lower_dn.end_with?(ldap_config['base'].downcase) ? ldap_config['name'] : nil
        else
          ldap_config.each_with_index do |config, i|
            if lower_dn.end_with?(config['base'].downcase)
              return config['name'].present? ? config['name'] : i
            end
          end
        end
        nil
      end

      def self.get_ldap_domain(login)
        ldap_config = self.ldap_config
        options = {:login => login,
                   :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                   :admin => ::Devise.ldap_use_admin_to_bind}

        for i in 0...(ldap_config.size)
          options[:domain] = ldap_config[i]['name']
          resource = Devise::LDAP::Connection.new(options)
          return ldap_config[i]['name'] if resource.search_for_login.present?
        end
        return nil
      end

      def self.valid_credentials?(login, password_plaintext, ldap_domain = nil)
        options = {:login => login,
                   :password => password_plaintext,
                   :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                   :admin => ::Devise.ldap_use_admin_to_bind,
                   :domain => ldap_domain || get_ldap_domain(login)}
        resource = Devise::LDAP::Connection.new(options)
        resource.authorized?(options[:domain])
      end

      def self.update_password(login, new_password, ldap_domain = nil)
        options = {:login => login,
                   :new_password => new_password,
                   :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                   :admin => ::Devise.ldap_use_admin_to_bind,
                   :domain => ldap_domain || get_ldap_domain(login)}

        resource = Devise::LDAP::Connection.new(options)
        resource.change_password!(options[:domain]) if new_password.present?
      end

      def self.update_own_password(login, new_password, current_password)
        set_ldap_param(login, ::Devise.ldap_password_attribute, ::Devise.ldap_auth_password_builder.call(new_password), current_password)
      end

      def self.ldap_connect(login, ldap_domain = nil)
        options = {:login => login,
                   :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                   :admin => ::Devise.ldap_use_admin_to_bind,
                   :domain => ldap_domain || get_ldap_domain(login)}

        resource = Devise::LDAP::Connection.new(options)
      end

      def self.valid_login?(login, ldap_domain = nil)
        self.ldap_connect(login, ldap_domain).valid_login?
      end

      def self.get_groups(login, ldap_domain = nil)
        ldap_domain ||= get_ldap_domain(login)
        self.ldap_connect(login, ldap_domain).user_groups(ldap_domain)
      end

      def self.in_ldap_group?(login, group_name, group_attribute = nil, ldap_domain = nil)
        ldap_domain ||= get_ldap_domain(login)
        self.ldap_connect(login, ldap_domain).in_group?(group_name, group_attribute, ldap_domain)
      end

      def self.get_dn(login, ldap_domain = nil)
        self.ldap_connect(login, ldap_domain).dn
      end

      def self.set_ldap_param(login, param, new_value, password = nil, ldap_domain = nil)
        self.set_ldap_params(login, {param => new_value}, password, ldap_domain)
      end

      def self.set_ldap_params(login, params, password = nil, ldap_domain = nil)
        options = { :login => login,
                    :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                    :password => password,
                    :admin => ::Devise.ldap_use_admin_to_bind,
                    :domain => ldap_domain || get_ldap_domain(login)}

        resource = Devise::LDAP::Connection.new(options)
        resource.set_params(params, options[:domain])
      end

      def self.delete_ldap_param(login, param, password = nil, ldap_domain = nil)
        self.delete_ldap_params(login, [param], password, ldap_domain)
      end

      def self.delete_ldap_params(login, params, password = nil, ldap_domain = nil)
        options = { :login => login,
                    :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                    :password => password,
                    :admin => ::Devise.ldap_use_admin_to_bind,
                    :domain => ldap_domain || get_ldap_domain(login)}

        resource = Devise::LDAP::Connection.new(options)
        resource.delete_params(params, options[:domain])
      end

      def self.get_ldap_param(login, param, ldap_domain = nil)
        resource = self.ldap_connect(login, ldap_domain)
        resource.ldap_param_value(param)
      end

      def self.get_ldap_entry(login, ldap_domain = nil)
        self.ldap_connect(login, ldap_domain).search_for_login
      end

      def self.delete_ldap_entry(login, password = nil, ldap_domain = nil)
        options = { :login => login,
                    :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                    :password => password,
                    :admin => ::Devise.ldap_use_admin_to_bind,
                    :domain => ldap_domain || get_ldap_domain(login)}
        resource = Devise::LDAP::Connection.new(options)
        resource.delete_entry(ldap_domain)
      end

    end

  end

end
