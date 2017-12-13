require 'net/ldap'

if defined?(Net::LDAP)
  module LDAPWithPersistentConnections
    def open(*args, &block)
      if block_given?
        super(*args, &block)
      else
        begin
          local_connection = nil
          super(*args) do |ldap|
            local_connection = @open_connection
            @open_connection = nil
          end
        ensure
          @open_connection = local_connection
        end
      end
    end

    def closed?
      !@open_connection
    end

    def close
      @open_connection.close unless closed?
      @open_connection = nil
    end
  end
  Net::LDAP.send(:prepend, LDAPWithPersistentConnections)
end