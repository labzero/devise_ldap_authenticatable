require 'net/ldap'
class Net::LDAP
  original_open_method = instance_method(:open)
  
  define_method(:open) do |*args, &block|
    if block_given?
      original_open_method.bind(self).(*args, &block)
    else
      begin
        local_connection = nil
        original_open_method.bind(self).(*args) do |ldap|
          local_connection = @open_connection
          @open_connection = nil
        end
      ensure
        @open_connection = local_connection
      end
    end
  end

  define_method(:closed?) do
    !@open_connection
  end

  define_method(:close) do
    @open_connection.close unless closed?
    @open_connection = nil
  end
end