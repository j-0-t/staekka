# Advanced Post Exploitation
module Msf
  module Sessions
    #
    # adding caching support
    # adds @cache to session for storing data in session/memory
    #
    module SessionCaching
      attr_accessor :cache

      def initialize(*args)
        start_cache
        super
      end

      #
      # starting the cache
      #
      def start_cache
        @cache = Cache.new unless @cache
      end

      #
      # the cache class
      #
      class Cache
        attr_accessor :data
        def initialize
          @data = {}
        end

        #
        # add a key and a value to the @data Hash
        #
        def add(key, value)
          @data[key] = value
        end

        #
        # read the value from a key
        #
        def read(key)
          @data[key]
        end

        #
        # delete a key
        #
        def delete(key)
          @data.delete(key)
        end

        #
        # check if a key exists
        #
        def exists?(key)
          @data.key?(key)
        end

        #
        # delete everything in cache
        #
        def delete_all
          @data = {}
        end
      end
    end
  end
end
