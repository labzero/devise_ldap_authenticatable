module Devise
  module LDAP
    class Connection
      POOLING_LDAP_OPTIONS = [:host, :port, :auth, :base, :encryption, :admin].freeze

      attr_reader :ldap, :login

      def initialize(params = {})
        ldap_options = params
        @ldap_domain= ldap_options[:domain]
        raw_config = Devise::LDAP::Adapter.ldap_config
        if raw_config.is_a?(Hash)
          ldap_config = raw_config
        elsif @ldap_domain.is_a?(Symbol) || @ldap_domain.is_a?(String)
          ldap_config = raw_config.find{ |config| config['name'] == @ldap_domain}
        else
          ldap_config = raw_config[@ldap_domain.to_i]
        end

        ldap_config = ldap_config.with_indifferent_access

        if ldap_config["ssl"]
          ldap_options[:encryption] = case ldap_config['ssl']
          when true
            :simple_tls
          when Hash
            ssl_hash = {}
            ssl_hash[:method] = (ldap_config['ssl']['method'] || :simple_tls).to_sym
            ssl_hash[:tls_options] = {}
            (ldap_config['ssl']['tls_options'] || {}).each do |key, value|
              ssl_hash[:tls_options][key.to_sym] = value
            end
            ssl_hash
          else
            ldap_config['ssl'].to_sym
          end
        end

        @ldap = if Thread.current['ldap_connection_sharing_enabled']
          hash = hash_ldap_config(ldap_config, ldap_options)
          Thread.current['ldap_shared_connection'] ||= {}
          Thread.current['ldap_shared_connection'][hash] ||= build_ldap_connection(ldap_config, ldap_options)
        else
          build_ldap_connection(ldap_config, ldap_options)
        end
        
        @attribute = ldap_config["attribute"]
        @allow_unauthenticated_bind = ldap_config["allow_unauthenticated_bind"]

        @ldap_auth_username_builder = params[:ldap_auth_username_builder]

        @group_base = ldap_config["group_base"]
        @check_group_membership = ldap_config.has_key?("check_group_membership") ? ldap_config["check_group_membership"] : ::Devise.ldap_check_group_membership
        @required_groups = ldap_config["required_groups"]
        @required_attributes = ldap_config["require_attribute"]

        @ldap.auth ldap_config["admin_user"], ldap_config["admin_password"] if params[:admin]
        @ldap.auth params[:login], params[:password] if ldap_config["admin_as_user"]

        @login = params[:login]
        @password = params[:password]
        @new_password = params[:new_password]
      end

      def delete_param(param, ldap_domain)
        update_ldap([[:delete, param.to_sym, nil]], ldap_domain)
      end

      def set_param(param, new_value, ldap_domain)
        update_ldap({ param.to_sym => new_value }, ldap_domain)
      end

      def set_params(params, ldap_domain)
        update_ldap(params, ldap_domain)
      end

      def delete_entry(ldap_domain)
        if ::Devise.ldap_use_admin_to_bind
          privileged_ldap = Connection.admin(ldap_domain)
        else
          authenticate!
          privileged_ldap = self.ldap
        end
        privileged_ldap.delete dn: dn
      end

      def delete_params(params, ldap_domain)
        if params.is_a?(Hash)
          operations = params.collect { |param, value| [:delete, param, value] }
        else
          operations = params.collect { |param| [:delete, param, nil] }
        end
        update_ldap(operations, ldap_domain)
      end

      def dn(connection=nil)
        connection ||= @ldap
        @dn ||= begin
          DeviseLdapAuthenticatable::Logger.send("LDAP dn lookup: #{@attribute}=#{@login}")
          ldap_entry = search_for_login(connection)
          if ldap_entry.nil?
            @ldap_auth_username_builder.call(@attribute,@login,connection)
          else
            ldap_entry.dn
          end
        end
      end

      def primary_group_sid
        unless @primary_group_sid
          return nil unless @login_ldap_entry.respond_to?(:objectSid) && @login_ldap_entry.respond_to?(:primaryGroupID)
          primary_group_id = @login_ldap_entry.primaryGroupID
          return nil if primary_group_id.blank?
          object_sid_array = @login_ldap_entry.objectSid
          return nil if object_sid_array.blank?
          object_sid = binary_sid_to_string(object_sid_array[0]).split('-')
          object_sid.delete_at(-1)
          primary_group_sid_base = object_sid.join('-')
          @primary_group_sid = primary_group_sid_base + '-' + primary_group_id[0]
        end
        @primary_group_sid
      end

      def primary_group_dn(admin_ldap_connection)
        return nil if primary_group_sid.blank?
        result = admin_ldap_connection.search(filter: "objectSid=#{primary_group_sid}")
        if result.present?
          return result[0].dn 
        else
          DeviseLdapAuthenticatable::Logger.send("No primary group found with objectSid: #{primary_group_sid}")
          return nil # Don't want to return an empty array in the case where that is the value of `result`
        end
      end

      def ldap_param_value(param)
        ldap_entry = search_for_login

        if ldap_entry
          unless ldap_entry[param].empty?
            value = ldap_entry.send(param)
            DeviseLdapAuthenticatable::Logger.send("Requested param #{param} has value #{value}")
            value
          else
            DeviseLdapAuthenticatable::Logger.send("Requested param #{param} does not exist")
            value = nil
          end
        else
          DeviseLdapAuthenticatable::Logger.send("Requested ldap entry does not exist")
          value = nil
        end
      end

      def authenticate!
        return false unless (@password.present? || @allow_unauthenticated_bind)
        @ldap.auth(dn, @password)
        @ldap.bind
      end

      def authenticated?
        authenticate!
      end

      def authorized?(ldap_domain)
        DeviseLdapAuthenticatable::Logger.send("Authorizing user #{dn}")
        if !authenticated?
          DeviseLdapAuthenticatable::Logger.send("Not authorized because not authenticated.")
          return false
        elsif !in_required_groups?
          DeviseLdapAuthenticatable::Logger.send("Not authorized because not in required groups.")
          return false
        elsif !has_required_attribute?(ldap_domain)
          DeviseLdapAuthenticatable::Logger.send("Not authorized because does not have required attribute.")
          return false
        else
          return true
        end
      end

      def change_password!(ldap_domain)
        update_ldap({:userpassword => Net::LDAP::Password.generate(:sha, @new_password)}, ldap_domain)
      end

      def in_required_groups?
        return true unless @check_group_membership

        ## FIXME set errors here, the ldap.yml isn't set properly.
        return false if @required_groups.nil?

        for group in @required_groups
          if group.is_a?(Array)
            return false unless in_group?(group[1], group[0])
          else
            return false unless in_group?(group)
          end
        end
        return true
      end

      def in_group?(group_name, group_attribute = LDAP::DEFAULT_GROUP_UNIQUE_MEMBER_LIST_KEY, ldap_domain)
        admin_ldap = Connection.admin(ldap_domain)
        unless ::Devise.ldap_ad_group_check
          admin_ldap.search(:base => group_name, :scope => Net::LDAP::SearchScope_BaseObject) do |entry|
            if entry[group_attribute].include? dn
              return true
            end
          end
        else
          # AD optimization - extension will recursively check sub-groups with one query
          # "(memberof:1.2.840.113556.1.4.1941:=group_name)"
          # Search both the user's group and the Domain User groups
          [dn, primary_group_dn(admin_ldap)].each do |distinguished_name|
            next if distinguished_name.blank?
            search_result = admin_ldap.search(:base => distinguished_name,
                                              :filter => Net::LDAP::Filter.ex("memberof:1.2.840.113556.1.4.1941", group_name),
                                              :scope => Net::LDAP::SearchScope_BaseObject)
            # Will return  the user entry if belongs to group otherwise nothing
            if search_result.length == 1 && search_result[0].dn.eql?(distinguished_name)
              return true
            end
          end
        end

        DeviseLdapAuthenticatable::Logger.send("User #{dn} is not in group: #{group_name}")
        false
      end

      def has_required_attribute?(ldap_domain)
        return true unless ::Devise.ldap_check_attributes

        admin_ldap = Connection.admin(ldap_domain)

        user = find_ldap_user(admin_ldap)

        @required_attributes.each do |key,val|
          unless user[key].include? val
            DeviseLdapAuthenticatable::Logger.send("User #{dn} did not match attribute #{key}:#{val}")
            return false
          end
        end

        return true
      end

      def user_groups(ldap_domain)
        admin_ldap = Connection.admin(ldap_domain)
        DeviseLdapAuthenticatable::Logger.send("Getting groups for #{dn}")
        groups = []
        [dn, primary_group_dn(admin_ldap)].each do |distinguished_name|
          next if distinguished_name.blank?
          filter = Net::LDAP::Filter.eq("member", distinguished_name)
          groups << admin_ldap.search(:filter => filter, :base => @group_base)
        end
        groups.flatten
      end

      def valid_login?
        !search_for_login.nil?
      end

      # Searches the LDAP for the login
      #
      # @return [Object] the LDAP entry found; nil if not found
      def search_for_login(connection=nil)
        connection ||= @ldap
        @login_ldap_entry ||= begin
          DeviseLdapAuthenticatable::Logger.send("LDAP search for login: #{@attribute}=#{@login}")
          filter = Net::LDAP::Filter.eq(@attribute.to_s, @login.to_s)
          ldap_entry = nil
          match_count = 0
          connection.search(:filter => filter) {|entry| ldap_entry = entry; match_count+=1}
          DeviseLdapAuthenticatable::Logger.send("LDAP search yielded #{match_count} matches")
          ldap_entry
        end
      end

      private

      def self.admin(ldap_domain)
        ldap = Connection.new(:admin => true, :domain => ldap_domain).ldap

        unless ldap.bind
          DeviseLdapAuthenticatable::Logger.send("Cannot bind to admin LDAP user")
          raise DeviseLdapAuthenticatable::LdapException, "Cannot connect to admin LDAP user"
        end

        return ldap
      end

      def find_ldap_user(ldap)
        DeviseLdapAuthenticatable::Logger.send("Finding user: #{dn}")
        ldap.search(:base => dn, :scope => Net::LDAP::SearchScope_BaseObject).try(:first)
      end

      def update_ldap(ops, ldap_domain)
        operations = []
        if ops.is_a? Hash
          ops.each do |key,value|
            operations << [:replace,key,value]
          end
        elsif ops.is_a? Array
          operations = ops
        end

        if ::Devise.ldap_use_admin_to_bind
          privileged_ldap = Connection.admin(ldap_domain)
        else
          authenticate!
          privileged_ldap = self.ldap
        end

        DeviseLdapAuthenticatable::Logger.send("Modifying user #{dn}")
        privileged_ldap.modify(:dn => dn, :operations => operations)
      end

      def binary_sid_to_string(binary)
        sid = []
        revision = binary[0].ord
        raise 'Unknown revision' if revision != 1
        sid << revision
        segment_count = binary[1].ord
        raise 'invalid binary length' if binary.bytesize != (segment_count * 4) + 8 # 2 bytes for version and length, 6 bytes for extra wide first segment
        high_bits, low_bits = binary.byteslice(2..7).unpack('nN')
        sid << (high_bits << 32) + low_bits
        sid << binary.byteslice(8..-1).unpack('V*')
        'S-' + sid.flatten.join('-')
      end

      def hash_ldap_config(ldap_config, ldap_options)
        hash = ''

        POOLING_LDAP_OPTIONS.each do |key|
          hash += "<#{key}:#{ldap_options[key]}>" if ldap_options[key]
        end

        ldap_config.keys.sort!.each do |key|
          hash += "<#{key}:#{ldap_config[key]}>"
        end
        Digest::SHA2.digest(hash)
      end

      def build_ldap_connection(config, options)
        ldap = Net::LDAP.new(options)
        ldap.host = config["host"]
        ldap.port = config["port"]
        ldap.base = config["base"]
        ldap
      end

    end
  end
end
