require 'net/ldap'

if defined?(Net::LDAP)
  class Net::LDAP
    def open_with_persistent_connection(*args, &block)
      if block_given?
        open_without_persistent_connection(*args, &block)
      else
        begin
          local_connection = nil
          open_without_persistent_connection(*args) do |ldap|
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

    alias_method_chain :open, :persistent_connection
  end
end