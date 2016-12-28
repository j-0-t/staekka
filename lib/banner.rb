# Advanced Post Exploitation

module Msf
  module Staekka
    # A simple startup banner
    module Banner
      #logo =
      #  '
      #       Staekka Metasploit Shell
      #  '.freeze
      Logo = File.read(File.dirname(__FILE__) + '/logos/staekka.txt').freeze

      def self.to_s
        Logo
      end
    end
  end
end
